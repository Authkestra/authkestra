# authkestra-policy

A **proof-of-concept** authorization policy engine for the `authkestra` framework, built on
[AWS Cedar](https://www.cedarpolicy.com/). Authentication answers "who are you?"; this answers
"may you do this?" — in a policy language that lives outside the binary, instead of in
hand-rolled `if role == "admin"` branches.

Proposed in [authkestra#21](https://github.com/Authkestra/authkestra/issues/21). The full
integration plan is [`docs/rfc-008-policy-engine.md`](../../docs/rfc-008-policy-engine.md).

## Status: proof of concept

The engine works and is tested, but **nothing calls it yet**. There is no `authkestra-resource`
guard, no axum/actix extractor, and no policy storage in `authkestra-op`. Those are designed in
RFC-008 and deliberately not built here, so the design can be reviewed before it acquires
dependents. The public API should be expected to change.

## The one structural rule

The engine performs no I/O. Cedar evaluates against an *entity store* — the principal, the
resource, their groups and attributes — and every byte of it arrives through a caller-supplied
`ResourceLoader`:

```text
AuthorizationRequest ──▶ PolicyEngine ──▶ ResourceLoader ──▶ your database
                              │                              (unreachable from the engine)
                              ▼
                       cedar_policy::Authorizer ──▶ Decision
```

That is authkestra#21's "no direct DB queries from the engine" criterion made structural rather
than a convention: the engine holds no storage handle, so it cannot query one by accident. It is
the same database-agnosticism rule `AGENTS.md` states for `UserStore` and `SessionStore`.

## Usage

A doctest in `src/lib.rs` exercises this same flow (plus a reload), so it is compiled and run by
`cargo test -p authkestra-policy` — this README is not.

```rust
use authkestra_policy::cedar_policy::RestrictedExpression;
use authkestra_policy::{
    AuthorizationRequest, EntityRecord, MemoryResourceLoader, PolicyEngine, parse_entity_uid,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
// Entities: alice is in the "eng" group, and the document is owned by that group.
let loader = MemoryResourceLoader::new();
loader.extend([
    EntityRecord::new(parse_entity_uid(r#"User::"alice""#)?)
        .parent(parse_entity_uid(r#"Group::"eng""#)?),
    EntityRecord::new(parse_entity_uid(r#"Group::"eng""#)?),
    EntityRecord::new(parse_entity_uid(r#"Doc::"design""#)?).attribute(
        "owner",
        RestrictedExpression::new_entity_uid(parse_entity_uid(r#"Group::"eng""#)?),
    ),
]);

let engine = PolicyEngine::builder()
    .policies(r#"
        @id("eng-reads-own-docs")
        permit(principal in Group::"eng", action == Action::"read", resource)
        when { resource.owner == Group::"eng" };
    "#)
    .loader(loader)
    .build()?;

let request = AuthorizationRequest::builder()
    .principal_str(r#"User::"alice""#)
    .action_str(r#"Action::"read""#)
    .resource_str(r#"Doc::"design""#)
    .build()?;

let decision = engine.is_authorized(&request).await?;
assert!(decision.is_allowed());
assert_eq!(decision.reasons(), ["eng-reads-own-docs"]);

Ok(())
}
```

### Evaluation errors: a skipped `forbid` is refused, not allowed

Cedar skips a policy that raises an evaluation error (a missing attribute, a type error) and
finishes the request with the rest. If the skipped policy is a `forbid`, the naive result is an
`Allow` that was only reached because the denying rule never ran — a fail-open that
`is_allowed() == true` gives the caller no way to notice.

So this crate refuses to answer instead:

| decision | erroring policies | you get |
| --- | --- | --- |
| `Allow` | at least one `forbid` | `Err(PolicyError::UnreliableDecision { errors })` |
| `Allow` | `permit`s only | `Ok(allow)` — another permit matched; errors in `Decision::errors()` |
| `Deny` | any | `Ok(deny)` — nothing skipped could have turned a Deny into an Allow |

Every evaluation error is logged at `warn` with the policy id either way, so a rule that has
quietly stopped evaluating is visible before it becomes an outage.

### Runtime reload

`PolicyEngine::reload(&self, cedar_source: &str)` swaps the policy set in place, so an operator
can change rules without a redeploy. It is all-or-nothing: the new text is parsed (and validated
against the schema, when one is configured) *before* the write lock is taken, so a syntax error
in an operator's update leaves the previous policies serving traffic rather than emptying the
policy set.

```rust,ignore
assert!(engine.reload("permit(principal").is_err());   // old policies still in force
engine.reload(new_source)?;                            // effective for the next request
```

### Policy ids in diagnostics

`Decision::reasons()` returns the ids of the policies that decided the request. Cedar's own
parser names them `policy0`, `policy1`, … by source order, which means inserting a rule at the
top of a file renumbers everything below it. This crate uses a policy's `@id("...")` annotation
as its id when present, so an audit log entry names the *rule* and keeps meaning across edits.

A policy with no `@id` keeps Cedar's positional id — `policy2` for the third policy in the file,
whether or not the two above it are annotated. Because those names are handed out positionally,
**`@id("policy0")`, `@id("policy7")` and anything else matching `policy<digits>` are rejected**
(`PolicyError::ReservedPolicyId`): such an id would collide with whichever un-annotated policy
happens to land on that line, and a diagnostic naming the wrong rule is worse than no diagnostic.
Names that merely start with `policy`, like `policy-admin-override`, are fine.

### Schema validation (optional)

Supplying a Cedar schema via `.schema(..)` turns on two things: policies are validated at load
time (a policy naming an action the schema does not declare is rejected instead of silently
never matching), and each request's context is type-checked for that action. Whether it should
be mandatory is an open maintainer decision — see RFC-008.

## Performance

`cargo test -p authkestra-policy --all-features -- --ignored --nocapture perf_smoke` measures
evaluation latency against a 10-policy RBAC set and a 414-entity store. Recorded numbers and
what they imply for a per-request guard are in RFC-008 §7.
