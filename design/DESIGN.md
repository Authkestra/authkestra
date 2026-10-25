# Authkestra Design System

The canonical values live in [`tokens.css`](./tokens.css). This file is the
argument for them and the rules for using them. When the two disagree,
`tokens.css` wins for values and this file wins for intent.

Consumers copy `tokens.css` verbatim:

| Surface | Repo | Copy lands at |
| --- | --- | --- |
| Playground | `Authkestra/playground` | `apps/web/app/tokens.css` |
| Docs | `Authkestra/docs` | `src/styles/tokens.css` |
| Landing | `Authkestra/landing` | `src/styles/tokens.css` |

Each copy carries a header saying where it came from. Change the canonical file,
then re-copy — never patch a copy in place.

---

## 1. The one idea

**The ground is neutral. Rust is the accent.**

Authkestra's ground is zinc-on-near-black, the same `#09090b` the documentation
has always used. Rust orange is not the background, the card, the panel, or the
page tint. It marks the single thing on a screen that matters — the primary
action, the step you are on, the link you are meant to click — and nothing else.

This is not a preference. A brand colour spread across surfaces that carry no
meaning is a brand colour that can no longer point at anything. If more than one
element on a screen is orange, at most one of them is right.

The reference is Rust's own material: black, white, and that orange, used
sparingly.

### What this replaces

The playground briefly tinted its entire ground warm (`20 30% 5%` and friends).
That reads as a second, unrelated decision sitting next to the docs' cool grey,
and it left the accent with nothing to distinguish itself from. The neutral ramp
below is the docs' ramp exactly, so a playground screenshot and a docs page are
visibly the same product.

---

## 2. Colour

### Neutrals — the ground

| Role | Token | Hex | Used for |
| --- | --- | --- | --- |
| Page | `--background` | `#09090b` | The window. Nothing else is this dark. |
| Card | `--card` | `#18181b` | A surface raised off the page. |
| Popover | `--popover` | `#27272a` | A surface raised off a card. |
| Border | `--border` | `#27272a` | Hairlines, dividers, card edges. |
| Input | `--input` | `#3f3f46` | Control edges — must survive on a card. |
| Body text | `--muted-foreground` | `#a1a1aa` | The default reading voice. |
| Heading | `--foreground` | `#fafafa` | Headings, and the one line read first. |

Depth comes from the surface step, not from a shadow. On this ground a shadow is
nearly invisible; a card that is `#18181b` on `#09090b` needs no border to read
as raised, and adding one anyway is how a UI ends up looking boxed.

`--foreground` is a budget. If every line on a card is `#fafafa`, nothing on that
card has emphasis. Prose is `--muted-foreground`.

### Rust — the accent

| Step | Hex | Contrast | Use |
| --- | --- | --- | --- |
| `--ak-rust-400` | `#f4845f` | 7.8:1 on page | Rust as **text**: links, ghost buttons, active step numeral |
| `--ak-rust-500` | `#e85d2f` | 5.7:1 on page | Icons, focus ring, accent rules |
| `--ak-rust-600` | `#ce422b` | 4.7:1 w/ white | The mark. Logo and favicon only. |
| `--ak-rust-700` | `#b7410e` | 5.6:1 w/ white | **Filled** primary buttons |
| `--ak-rust-950` | `#3b1408` | — | Tinted ground behind accent text |

Two roles exist because no single shade clears both directions. Reaching for the
wrong one ships an unreadable control, so ask for the job, not the shade:

- `--primary` + `--primary-foreground` → a filled thing you put white on.
- `--primary-accent` → the orange *is* the text.

`--brand` (`rust-600`) is the mark. It never appears in UI chrome.

### Verdicts

Success `#34d399` / `#047857` · warning `#facc15` / `#a16207` ·
danger `#fb7185` / `#be123c` · info `#60a5fa` / `#1d4ed8`.

Warning is pushed to a true yellow (hue 48) and danger to a crimson (345)
specifically so neither can be misread as "the accent, slightly off". With a
warm accent, an amber warning and a red error are three warm things competing.

Colour is never the only signal. Every verdict carries an icon and a word.

### Rules

1. One orange element per screen region — where "element" means a claim on the
   reader's attention. If two things in a region each say "look here", one of
   them is wrong.

   A *uniform set* is not two claims. Eight method icons in a grid, each
   styled identically, read as one repeated object: the accent is saying
   "these are the methods", once, not competing with itself eight times. The
   test is whether removing the accent from one member would look like a
   mistake — if yes, it is a set and it can be rust; if it would look like
   demoting that one thing, they were competing and only one should have had
   it. A set and a call to action must not both be rust in the same region.
2. Never tint a surface warm. `--card` is grey. Accent tint is
   `--primary-subtle` behind accent *text*, at panel scale at most.
3. Never hardcode a hex or a Tailwind palette class (`bg-slate-900`,
   `text-zinc-400`) in a component. Address colour through a role token only.
4. State is carried by the ring and the surface step, not by hue drift.

---

## 3. Type

**Inter** for everything a person reads. **JetBrains Mono** for everything a
compiler reads. No third face — a display face would have to beat tighter
tracking on Inter at 48px, and it does not.

| Step | Size | Tracking | Leading | Use |
| --- | --- | --- | --- | --- |
| `5xl` | 64px | tight | 1.15 | Hero, `lg:` and up only |
| `4xl` | 48px | tight | 1.15 | h1 |
| `3xl` | 36px | tight | 1.3 | h2 |
| `2xl` | 28px | tight | 1.3 | h3 |
| `xl` | 22px | snug | 1.3 | h4 |
| `lg` | 18px | snug | 1.65 | Lead paragraph |
| `base` | 16px | snug | 1.65 | Prose |
| `sm` | 14px | snug | 1.5 | **UI default** — labels, buttons, nav, tables |
| `xs` | 12px | snug | 1.5 | Badges, captions |
| `2xs` | 11px | wide | 1.5 | All-caps eyebrows only |

Tracking tightens as size grows. Inter at 48px with default tracking looks loose
beside the same face at 16px; `--ak-tracking-tight` fixes it.

Weights: 400 body, 500 UI labels and buttons, 600 headings, 700 h1 and hero.
Nothing else. 300 disappears on a dark ground; 800 is a different typeface.

Anything counting — a countdown, a token expiry, a diff line number — gets
`font-variant-numeric: tabular-nums`, or the row shuffles as it ticks.

Prose measure is `--ak-layout-prose` (68ch). App measure is 1200px.

---

## 4. Space, radius, elevation

Space is a 4px ramp (`--ak-space-*`). Marketing sections breathe at
`--ak-space-24` (96px); app panels at `--ak-space-6` (24px).

Radius derives from one knob, `--radius` (10px). Cards, buttons and inputs share
it so nothing looks bolted on. `--ak-radius-xl` (14px) is for code blocks and
large panels; `--ak-radius-full` is for pills and avatars and nothing else.

Elevation is three levels. Level 3 adds a `1px` inset white highlight at 4%,
which is what actually reads as *floating* in dark UI — the shadow alone does
not. `--ak-shadow-accent` is the one place a glow is allowed: the hero's primary
call to action.

---

## 5. Motion

Three durations (`fast` 120ms, `base` 200ms, `slow` 420ms) and two curves. Fast
is hover and focus. Base is disclosure. Slow is a panel arriving or a flow
advancing a step.

`--ak-ease-out` for anything entering or responding to a click — it front-loads
the movement, so the UI feels answered immediately. `--ak-ease-in-out` for
anything that loops.

Every non-decorative animation must honour `prefers-reduced-motion: reduce` by
settling into its end state rather than playing. The landing page's flow
animation is the main obligation here: reduced motion gets the finished diagram,
not a frozen first frame.

---

## 6. Icons

**Lucide, and only Lucide.** Mixing icon sets is the fastest way to make a
considered UI look assembled. Already a dependency in the playground
(`lucide-react`); the Astro sites use `lucide-static` or inline the paths.

Stroke `1.5` — it matches Inter's stem weight at body size; Lucide's default `2`
reads heavy next to it. Sizes: 16 inline with 14px text, 20 default, 24 section
headers, 32 feature cards.

Icons inherit `currentColor`. An icon is never the only label on an interactive
control.

### The working vocabulary

Fixing these means the same concept looks the same everywhere.

| Concept | Icon |
| --- | --- |
| Passkeys / WebAuthn | `fingerprint` |
| TOTP / authenticator | `smartphone` |
| OAuth2 / social sign-in | `key-round` |
| OIDC provider (OP) | `id-card` |
| Client credentials | `server` |
| Device flow | `tv-minimal` |
| Bot protection / CAPTCHA | `shield-check` |
| Device signatures | `badge-check` |
| Session | `circle-user` |
| Token / JWT | `ticket` |
| Storage / KV | `database` |
| Compile-time safety | `shield` |
| Framework adapter | `puzzle` |
| Stateless | `feather` |
| Diff / generated config | `file-diff` |
| Download starter kit | `package` |
| Run it live | `play` |
| Success | `circle-check` |
| Warning | `triangle-alert` |
| Error | `circle-alert` |
| Info | `info` |

---

## 7. Component defaults

**Button** — 36px tall at `sm` text, weight 500, `--radius`. `primary` is
`--primary` fill with `--primary-foreground`. `secondary` is `--secondary` fill.
`ghost` is transparent with `--muted-foreground`, going to `--foreground` on
hover. `link` is `--primary-accent`, underlined on hover. Exactly one `primary`
per view.

**Card** — `--card` surface, `--border` hairline, `--radius`,
`--ak-space-6` padding. Title at `base`/600 `--foreground`, body at
`sm` `--muted-foreground`.

**Input** — `--background` (recessed, not raised), `--input` border,
`--ak-space-3` padding, `sm` text. Placeholder `--ak-neutral-500`.

**Focus** — one rule, global, never per-component:

```css
:focus-visible {
  outline: 2px solid hsl(var(--ring));
  outline-offset: 2px;
  border-radius: inherit;
}
```

`outline`, deliberately, and not the stacked `box-shadow` this system first
specified. A shadow-based ring loses a fight it should never be in: a component
carrying its own `shadow-sm` sets `box-shadow` from Tailwind's *utility* layer,
which outranks a rule in the `base` layer, so the ring silently vanishes on
exactly the controls that have any elevation — secondary buttons, inputs,
switches. `outline` occupies a property nothing else competes for, follows
`border-radius` in every current browser, and `outline-offset` gives the gap the
double shadow was faking.

Auth flows are keyboard-heavy; a component that styles its own focus is a
component that will eventually have none.

**Code** — JetBrains Mono, `--ak-neutral-800` inline ground,
`--ak-radius-xl` block with a `--border` hairline.

Syntax highlighting runs on brightness first and hue second, through the
`--code-*` roles. The brightest thing in a line is the function or method being
called (`--code-fn`), because that is usually the part that distinguishes one
snippet from the next; plain code sits a step below it and a comment a step
below that. Only three hues carry meaning — keyword, type, literal — because a
snippet coloured like a rainbow is harder to read than one that colours only
what separates its lines.

The three hues are warm and fan out from the rust ramp — coral at 16, amber at
35, olive at 75 — close enough to read as one family. On a page about a Rust
library, code is the last place that should look like someone else's editor.

Hue is what that family gives up, so it is not what tells the three apart:
inside a 60° arc, red-green colour-vision deficiency flattens all three to the
same tan. **Lightness carries the distinction instead**, and the three sit at
deliberately different ramp steps — coral 79%, amber 62%, olive 81% — so they
interleave with the neutral code roles rather than stack against them. Measured
under a Machado et al. (2009) deuteranopia/protanopia simulation, the tightest
of the fifteen code-role pairs separates by ΔL* 3.6. That is a floor, not
headroom: six roles share the L* 66.5–98.3 band, so a further distinction needs
a non-colour cue rather than a fourth hue.

Keywords take `--ak-coral-200`, two steps lighter than the accent rather than
one, so the family reads while the exact accent shade stays reserved for links
and calls to action; a `let` should never look clickable. One step did not
deliver that — `--ak-rust-300` sat 1.27:1 from the accent and 1° of hue away,
which is not a perceptible step at 13px.

**This depends on where liveness is marked.** Inside a code block the accent's
only other job is to say which line or which snippet is live, and that mark has
to stay distinguishable. A surface that marks liveness *inside* the block cannot
also have warm keywords — there would be nothing for the mark to stand out
against — and its highlighting must stay cool. The landing page marks liveness
outside the block: the diagram lights the active route and the panel shows that
route's code, which is what leaves the palette free.

---

## 8. The mark

![The Authkestra mark](./logo/mark-on-dark.svg)

An **A**, drawn as two converging strokes with a rust crossbar where an arch
would carry its keystone. The crossbar is the whole idea: in an arch the
keystone is the piece that makes the structure hold, which is the typestate
argument in one object. It is also the only part that is rust.

Two things it deliberately is not. It is not a **shield, lock, key or
fingerprint** — that is the default every authentication product reaches for,
and this system already spends `fingerprint` and `key-round` as *content* icons
(§6), so reusing one as the mark would make the brand look like a feature. And
it is not the *orchestra* in the name: several marks were drawn from converging
strokes and bars, and every one of them read as a crown, a fountain or an
equalizer before it read as a letter. That idea survives where it has motion and
room — the landing page's flow animation — rather than where it has 16 pixels.

### Files

| File | Use |
| --- | --- |
| `logo/mark.svg` | The mark. Takes its ink from `currentColor`; rust bar fixed. |
| `logo/mark-on-dark.svg` | Explicit `#fafafa` ink, for `<img>` contexts. |
| `logo/mark-on-light.svg` | Explicit `#18181b` ink, same reason. |
| `logo/favicon.svg` | Follows the browser theme via `prefers-color-scheme`. |
| `logo/apple-touch-icon.png` | 180px, on a solid `#09090b` ground. |
| `logo/icon-192.png`, `icon-512.png` | PWA / manifest / social. |

`currentColor` resolves to black inside an `<img>`, which is how GitHub renders
a README SVG — so a mark embedded that way must use an explicit-ink file, or it
turns invisible on a dark README.

### Rules

**Minimum size is 16px.** The mark was chosen because it is still a letter at
favicon size; nothing below that is supported. Do not add detail to compensate
at large sizes — it scales as drawn.

**Clear space** on all four sides is the height of the crossbar — `2.8` units on
the 32-unit grid, so `0.0875 × size`. At 32px that is 3px. Nothing else sits in
it, including the wordmark.

**The lockup** is the mark beside `Authkestra` set in Inter 600, optically
centred, with the wordmark's cap height matching the mark's height and a gap of
`0.4 × size`. There is no lockup SVG on purpose: outlining the wordmark would
fork the typeface, and every surface that needs a lockup already has Inter.

**Colour.** The crossbar is `--brand` (rust-600, `#ce422b`) and nothing else in
the mark is ever rust. The strokes take the ink of whatever they sit on. A
single-colour rendering — the crossbar in the ink too — is allowed where colour
is unavailable (an engraving, a fax, a one-colour print) and nowhere else.

**Do not** recolour the crossbar, rotate the mark, add a container shape or
outline, apply a gradient or shadow, stretch either axis independently, or place
it on a background that leaves the strokes under 4.5:1. On a busy image, put it
on a solid `--background` plate rather than knocking it out.

## 9. Checklist

Before shipping a screen:

- [ ] No hex literal and no Tailwind palette class in any component.
- [ ] At most one orange element per screen region.
- [ ] No warm-tinted surface.
- [ ] Body copy is `--muted-foreground`; `--foreground` is spent on ≤2 things.
- [ ] Every icon is Lucide at stroke 1.5.
- [ ] Every verdict pairs colour with an icon and a word.
- [ ] Focus is visible on every interactive element via the global ring.
- [ ] Counting numerals are tabular.
- [ ] `prefers-reduced-motion` settles animations rather than freezing them.
- [ ] The mark has its clear space, is at least 16px, and its crossbar is the only rust in it.
