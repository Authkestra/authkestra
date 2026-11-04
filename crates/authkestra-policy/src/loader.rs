//! Entity hydration: the only door between the policy engine and your data.
//!
//! Cedar evaluates policies against an *entity store* — the principal, the resource, the groups
//! they belong to, and their attributes. Somebody has to fetch that. Per authkestra#21's
//! acceptance criteria the engine must never do it itself, so it holds a
//! `Box<dyn ResourceLoader>` (the workspace's `Box<dyn Trait>` preference for I/O-bound paths,
//! see `AGENTS.md`) and asks for exactly the entities one request needs.
//!
//! That boundary is what keeps this crate database-agnostic in the same sense as `UserStore` and
//! `SessionStore`: an implementation can hit Postgres, an in-memory cache, an HTTP service, or a
//! test fixture, and the engine cannot tell the difference.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use async_trait::async_trait;
use cedar_policy::{Entities, Entity, EntityUid, EvalResult, RestrictedExpression, Schema};

use crate::error::PolicyError;
use crate::request::AuthorizationRequest;

/// Hydrates the Cedar entities needed to decide one request.
///
/// Implementations should return the principal, the resource, the action (when policies use
/// action groups), and everything reachable from them that policies may read — group
/// memberships in particular, since Cedar's `in` operator walks the parent hierarchy.
///
/// Returning *fewer* entities than the policies reference is not an error: Cedar treats an
/// absent entity as having no attributes and no parents, so an under-hydrated store silently
/// biases towards deny. Returning too many is merely wasteful. Neither is checked here.
#[async_trait]
pub trait ResourceLoader: Send + Sync {
    /// Fetch the entity store for `request`.
    ///
    /// Storage faults should surface as [`PolicyError::Loader`] (see [`PolicyError::loader`]);
    /// the engine propagates them to the caller instead of turning them into a deny, so that
    /// "the database is down" is never silently indistinguishable from "you are not allowed".
    async fn load_entities(&self, request: &AuthorizationRequest) -> Result<Entities, PolicyError>;
}

/// A loader that hands back the same fixed entity set for every request.
///
/// Right for small, wholly-in-memory hierarchies (a config file of roles) and for tests. Wrong
/// for anything per-tenant or large: the trait returns entities *by value*, so every request
/// pays a full clone of the set — see `docs/rfc-008-policy-engine.md` for the measured cost and
/// the `Arc<Entities>` alternative under consideration.
#[derive(Debug, Clone, Default)]
pub struct StaticResourceLoader {
    entities: Entities,
}

impl StaticResourceLoader {
    /// Wrap an already-built entity set.
    pub fn new(entities: Entities) -> Self {
        Self { entities }
    }

    /// An empty store. Policies that only match on UIDs (`principal == User::"alice"`) need no
    /// entity data at all, so this is a legitimate production choice, not just a test stub.
    pub fn empty() -> Self {
        Self {
            entities: Entities::empty(),
        }
    }

    /// Build from Cedar's entity JSON format — the shape you would store in a column, a file, or
    /// return from an admin API.
    pub fn from_json_str(json: &str, schema: Option<&Schema>) -> Result<Self, PolicyError> {
        let entities = Entities::from_json_str(json, schema)
            .map_err(|e| PolicyError::Entities(format!("could not parse entity JSON: {e}")))?;
        Ok(Self { entities })
    }

    /// The entity set this loader serves.
    pub fn entities(&self) -> &Entities {
        &self.entities
    }
}

#[async_trait]
impl ResourceLoader for StaticResourceLoader {
    async fn load_entities(
        &self,
        _request: &AuthorizationRequest,
    ) -> Result<Entities, PolicyError> {
        Ok(self.entities.clone())
    }
}

/// One entity as held by [`MemoryResourceLoader`]: a UID, attributes, and *direct* parents.
///
/// Parents are stored un-closed; the transitive closure is computed by
/// `Entities::from_entities` when the request's slice is assembled. Storing direct edges is what
/// a relational schema would hold too (a `group_members` row is one edge), so this mirrors the
/// shape a real loader would read.
#[derive(Debug, Clone)]
pub struct EntityRecord {
    uid: EntityUid,
    attributes: HashMap<String, RestrictedExpression>,
    parents: HashSet<EntityUid>,
}

impl EntityRecord {
    /// A record with no attributes and no parents.
    pub fn new(uid: EntityUid) -> Self {
        Self {
            uid,
            attributes: HashMap::new(),
            parents: HashSet::new(),
        }
    }

    /// Add an attribute, e.g. `.attribute("owner", RestrictedExpression::new_string("alice"))`.
    pub fn attribute(mut self, name: impl Into<String>, value: RestrictedExpression) -> Self {
        self.attributes.insert(name.into(), value);
        self
    }

    /// Add a direct parent (a group, a folder, an action group).
    pub fn parent(mut self, parent: EntityUid) -> Self {
        self.parents.insert(parent);
        self
    }

    /// This record's UID.
    pub fn uid(&self) -> &EntityUid {
        &self.uid
    }

    fn to_entity(&self) -> Result<Entity, PolicyError> {
        Entity::new(
            self.uid.clone(),
            self.attributes.clone(),
            self.parents.clone(),
        )
        .map_err(|e| {
            PolicyError::Entities(format!("entity {} has an invalid attribute: {e}", self.uid))
        })
    }
}

/// A mutable in-memory entity store that hydrates only what a request reaches.
///
/// This is the worked example of a *real* loader rather than a fixture: starting from the
/// request's principal, action, and resource it walks parent edges depth-first (a stack plus a
/// visited set, so the delivered sub-graph is the same whatever the traversal order) and returns
/// just that sub-graph, which is the same query a SQL-backed loader would issue (a recursive CTE
/// over the membership table) instead of `SELECT *`. It is also mutable at runtime — entities
/// can be inserted and removed while requests are being evaluated — so it exercises the
/// concurrency shape a production loader has.
#[derive(Debug, Default)]
pub struct MemoryResourceLoader {
    entities: RwLock<HashMap<EntityUid, EntityRecord>>,
}

impl MemoryResourceLoader {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a record.
    pub fn insert(&self, record: EntityRecord) {
        let mut guard = self.write();
        guard.insert(record.uid.clone(), record);
    }

    /// Insert several records.
    pub fn extend(&self, records: impl IntoIterator<Item = EntityRecord>) {
        let mut guard = self.write();
        for record in records {
            guard.insert(record.uid.clone(), record);
        }
    }

    /// Remove a record, returning whether it was present.
    pub fn remove(&self, uid: &EntityUid) -> bool {
        self.write().remove(uid).is_some()
    }

    /// How many records are held.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A poisoned lock is recovered rather than propagated: the map is a plain collection with
    /// no cross-field invariant, so a panic elsewhere cannot have left it half-updated, and
    /// failing every subsequent authorization because one unrelated task panicked would be a
    /// worse outcome than continuing.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<EntityUid, EntityRecord>> {
        self.entities.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<EntityUid, EntityRecord>> {
        self.entities.write().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl ResourceLoader for MemoryResourceLoader {
    async fn load_entities(&self, request: &AuthorizationRequest) -> Result<Entities, PolicyError> {
        let mut selected: Vec<Entity> = Vec::new();
        let mut seen: HashSet<EntityUid> = HashSet::new();
        let mut queue: Vec<EntityUid> = vec![
            request.principal.clone(),
            request.action.clone(),
            request.resource.clone(),
        ];

        {
            let store = self.read();
            while let Some(uid) = queue.pop() {
                // `seen` is what makes this terminate on a cyclic membership graph. Cedar
                // rejects such a hierarchy when it computes the transitive closure below, but
                // only if we get that far — without this check the walk itself would hang.
                if !seen.insert(uid.clone()) {
                    tracing::debug!(
                        entity = %uid,
                        "entity already hydrated for this request; not walking its parents again"
                    );
                    continue;
                }
                // A UID with no record is not an error: Cedar tolerates absent entities, and a
                // request naming an unknown principal must reach the authorizer so that it
                // produces a *default deny with diagnostics* rather than a loader failure.
                let Some(record) = store.get(&uid) else {
                    // Worth a log line even though it is legal: an unknown principal or
                    // resource is the most common reason a request comes back denied with no
                    // reason policies at all, and that is otherwise invisible.
                    tracing::debug!(
                        entity = %uid,
                        "no record for entity; continuing with it absent from the entity store"
                    );
                    continue;
                };
                queue.extend(record.parents.iter().cloned());
                // The `warn!` carries the UID only. The attribute *values* stay in the returned
                // error, which goes to the caller who owns the data; a log sink is a different
                // trust boundary and may be holding whatever an attribute happens to contain.
                let entity = record.to_entity().inspect_err(|e| {
                    tracing::warn!(
                        entity = %uid,
                        error_code = e.code(),
                        "entity could not be converted for evaluation; abandoning this request"
                    );
                })?;

                // Recursively inspect entity attributes and tags to extract all referenced entity UIDs
                // (and transitively their parents and dependencies) so forbid and permit policies evaluate correctly.
                let mut attr_uids = Vec::new();
                for (_attr_name, attr_val) in entity.attrs() {
                    if let Ok(eval_res) = attr_val {
                        extract_referenced_uids_from_eval_result(&eval_res, &mut attr_uids);
                    }
                }
                for (_tag_name, tag_val) in entity.tags() {
                    if let Ok(eval_res) = tag_val {
                        extract_referenced_uids_from_eval_result(&eval_res, &mut attr_uids);
                    }
                }
                if !attr_uids.is_empty() {
                    tracing::debug!(
                        entity = %uid,
                        attr_entity_count = attr_uids.len(),
                        "extracted referenced entity UIDs from attributes for recursive hydration"
                    );
                    queue.extend(attr_uids);
                }

                selected.push(entity);
            }
        }

        let count = selected.len();
        tracing::debug!(
            entity_count = count,
            principal = %request.principal,
            action = %request.action,
            resource = %request.resource,
            "hydrated entity store for request"
        );
        Entities::from_entities(selected, None).map_err(|e| {
            tracing::warn!(
                entity_count = count,
                error = %e,
                "hydrated entities do not form a valid store (duplicate uid, or a membership cycle)"
            );
            PolicyError::Entities(format!("could not assemble {count} entities: {e}"))
        })
    }
}

/// Recursively extracts all [`EntityUid`]s contained in an [`EvalResult`] (direct UIDs, sets, or records).
fn extract_referenced_uids_from_eval_result(res: &EvalResult, out: &mut Vec<EntityUid>) {
    match res {
        EvalResult::EntityUid(uid) => out.push(uid.clone()),
        EvalResult::Set(set) => {
            for elem in set.iter() {
                extract_referenced_uids_from_eval_result(elem, out);
            }
        }
        EvalResult::Record(rec) => {
            for (_key, val) in rec.iter() {
                extract_referenced_uids_from_eval_result(val, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::parse_entity_uid;

    fn uid(s: &str) -> EntityUid {
        parse_entity_uid(s).expect("valid uid")
    }

    fn request(principal: &str, action: &str, resource: &str) -> AuthorizationRequest {
        AuthorizationRequest::new(uid(principal), uid(action), uid(resource))
    }

    #[tokio::test]
    async fn static_loader_returns_its_fixed_set() {
        let loader = StaticResourceLoader::from_json_str(
            r#"[{ "uid": { "type": "User", "id": "alice" }, "attrs": {}, "parents": [] }]"#,
            None,
        )
        .expect("valid entity json");
        assert_eq!(loader.entities().iter().count(), 1);

        let entities = loader
            .load_entities(&request(
                r#"User::"bob""#,
                r#"Action::"view""#,
                r#"Doc::"x""#,
            ))
            .await
            .expect("static loader never fails");
        assert!(entities.get(&uid(r#"User::"alice""#)).is_some());
    }

    #[tokio::test]
    async fn static_loader_wraps_an_already_built_entity_set() {
        let entities =
            Entities::from_entities([Entity::with_uid(uid(r#"User::"alice""#))], None::<&Schema>)
                .expect("valid entity set");
        let loader = StaticResourceLoader::new(entities);

        let loaded = loader
            .load_entities(&request(
                r#"User::"alice""#,
                r#"Action::"view""#,
                r#"Doc::"x""#,
            ))
            .await
            .expect("static loader never fails");
        assert_eq!(loaded.iter().count(), 1);
    }

    #[tokio::test]
    async fn static_loader_rejects_malformed_entity_json() {
        let error = StaticResourceLoader::from_json_str("{ not json", None)
            .expect_err("malformed json is rejected");
        assert_eq!(error.code(), "entities");
    }

    #[tokio::test]
    async fn empty_static_loader_yields_no_entities() {
        let loader = StaticResourceLoader::empty();
        let entities = loader
            .load_entities(&request(r#"User::"a""#, r#"Action::"view""#, r#"Doc::"x""#))
            .await
            .expect("empty loader never fails");
        assert_eq!(entities.iter().count(), 0);
    }

    #[tokio::test]
    async fn memory_loader_hydrates_only_the_reachable_subgraph() {
        let loader = MemoryResourceLoader::new();
        loader.extend([
            EntityRecord::new(uid(r#"User::"alice""#)).parent(uid(r#"Group::"eng""#)),
            EntityRecord::new(uid(r#"Group::"eng""#)).parent(uid(r#"Group::"staff""#)),
            EntityRecord::new(uid(r#"Group::"staff""#)),
            // Reachable from neither the principal nor the resource of the request below.
            EntityRecord::new(uid(r#"User::"mallory""#)).parent(uid(r#"Group::"contractors""#)),
            EntityRecord::new(uid(r#"Group::"contractors""#)),
            EntityRecord::new(uid(r#"Doc::"readme""#))
                .attribute("owner", RestrictedExpression::new_string("alice".into())),
        ]);
        assert_eq!(loader.len(), 6);
        assert!(!loader.is_empty());

        let entities = loader
            .load_entities(&request(
                r#"User::"alice""#,
                r#"Action::"view""#,
                r#"Doc::"readme""#,
            ))
            .await
            .expect("hydration succeeds");

        // alice, eng, staff, readme — but not mallory or contractors.
        assert_eq!(entities.iter().count(), 4);
        assert!(entities.get(&uid(r#"Group::"staff""#)).is_some());
        assert!(entities.get(&uid(r#"User::"mallory""#)).is_none());
        assert!(entities.get(&uid(r#"Group::"contractors""#)).is_none());
    }

    #[tokio::test]
    async fn memory_loader_tolerates_unknown_uids() {
        let loader = MemoryResourceLoader::new();
        loader.insert(EntityRecord::new(uid(r#"User::"alice""#)));

        let entities = loader
            .load_entities(&request(
                r#"User::"alice""#,
                r#"Action::"view""#,
                r#"Doc::"missing""#,
            ))
            .await
            .expect("an unknown resource is not a loader error");
        assert_eq!(entities.iter().count(), 1);
    }

    #[tokio::test]
    async fn memory_loader_terminates_on_a_membership_cycle() {
        let loader = MemoryResourceLoader::new();
        loader.extend([
            EntityRecord::new(uid(r#"Group::"a""#)).parent(uid(r#"Group::"b""#)),
            EntityRecord::new(uid(r#"Group::"b""#)).parent(uid(r#"Group::"a""#)),
        ]);

        // Two separate properties: the traversal terminates at all (the `seen` set — without it
        // this call would hang, not fail), and Cedar itself rejects a cyclic hierarchy when it
        // computes the transitive closure, which surfaces as a plain `entities` error rather
        // than a panic.
        let error = loader
            .load_entities(&request(
                r#"Group::"a""#,
                r#"Action::"view""#,
                r#"Doc::"missing""#,
            ))
            .await
            .expect_err("cedar rejects cyclic entity hierarchies");
        assert_eq!(error.code(), "entities");
    }

    #[tokio::test]
    async fn memory_loader_reflects_removals() {
        let loader = MemoryResourceLoader::new();
        loader.insert(EntityRecord::new(uid(r#"User::"alice""#)));
        assert!(loader.remove(&uid(r#"User::"alice""#)));
        assert!(!loader.remove(&uid(r#"User::"alice""#)));
        assert!(loader.is_empty());

        let entities = loader
            .load_entities(&request(
                r#"User::"alice""#,
                r#"Action::"view""#,
                r#"Doc::"x""#,
            ))
            .await
            .expect("empty store is fine");
        assert_eq!(entities.iter().count(), 0);
    }

    #[tokio::test]
    async fn memory_loader_reports_an_attribute_that_cannot_be_evaluated() {
        // Cedar builds extension values lazily, so a malformed `ip(..)` argument is only caught
        // when the entity is constructed — inside the loader, on the request path. It must come
        // back as a `PolicyError`, not a panic.
        let loader = MemoryResourceLoader::new();
        loader.insert(
            EntityRecord::new(uid(r#"User::"alice""#))
                .attribute("last_seen_from", RestrictedExpression::new_ip("not-an-ip")),
        );

        let error = loader
            .load_entities(&request(
                r#"User::"alice""#,
                r#"Action::"view""#,
                r#"Doc::"x""#,
            ))
            .await
            .expect_err("the attribute cannot be evaluated");
        assert_eq!(error.code(), "entities");
        assert!(error.to_string().contains("alice"), "{error}");
    }

    #[test]
    fn entity_record_exposes_its_uid() {
        let record = EntityRecord::new(uid(r#"User::"alice""#));
        assert_eq!(record.uid(), &uid(r#"User::"alice""#));
    }

    #[tokio::test]
    async fn memory_loader_recursively_hydrates_attribute_entity_references_and_parents() {
        let loader = MemoryResourceLoader::new();

        // Target org and department
        let tech_corp = uid(r#"Org::"tech_corp""#);
        let eng_dept = uid(r#"Department::"engineering""#);
        loader.insert(EntityRecord::new(tech_corp.clone()));
        loader.insert(EntityRecord::new(eng_dept.clone()).parent(tech_corp.clone()));

        // Standby group and bob
        let standbys = uid(r#"Group::"standbys""#);
        let bob = uid(r#"User::"bob""#);
        loader.insert(EntityRecord::new(standbys.clone()));
        loader.insert(EntityRecord::new(bob.clone()).parent(standbys.clone()));

        // Alice referencing eng_dept via direct attribute, and bob via a set attribute
        let alice_uid = uid(r#"User::"alice""#);
        let alice = EntityRecord::new(alice_uid.clone())
            .attribute(
                "dept",
                RestrictedExpression::new_entity_uid(eng_dept.clone()),
            )
            .attribute(
                "delegates",
                RestrictedExpression::new_set(vec![RestrictedExpression::new_entity_uid(
                    bob.clone(),
                )]),
            );
        loader.insert(alice);

        let req = request(r#"User::"alice""#, r#"Action::"view""#, r#"Doc::"roadmap""#);
        let hydrated = loader
            .load_entities(&req)
            .await
            .expect("hydration succeeds");

        assert!(hydrated.get(&alice_uid).is_some(), "alice must be hydrated");
        assert!(
            hydrated.get(&eng_dept).is_some(),
            "attribute-referenced dept must be hydrated"
        );
        assert!(
            hydrated.get(&tech_corp).is_some(),
            "parent of attribute-referenced dept must be hydrated"
        );
        assert!(
            hydrated.get(&bob).is_some(),
            "set-attribute-referenced bob must be hydrated"
        );
        assert!(
            hydrated.get(&standbys).is_some(),
            "parent of set-attribute-referenced bob must be hydrated"
        );
    }
}
