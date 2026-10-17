# Design system

Asservat is a quiet workspace for choosing bounded actions and reading evidence. The [research and applied decisions](web-design-research.md) explain the overhaul. The [local CSS](../../design/ui/styles.css) is the visual reference. Production uses the accepted React/TypeScript console with compiled assets served by Go (ADR-046). React Aria supplies unstyled accessible primitives; native CSS preserves this visual system. The existing vanilla prototype remains design evidence.

## Visual foundation

| Token / component | Choice | Purpose |
| --- | --- | --- |
| Canvas / navigation | White / `#f8f9fa` | Keep content prominent and navigation quiet |
| Text / secondary | `#20252b` / `#5e6772` | Legible text with restrained hierarchy |
| Primary / selection | `#126b54` / `#eaf3ee` | Emphasize the next action and current section |
| Dividers / control borders | `#e3e6e9` / `#8a949e` | Subtle grouping; stronger boundaries for editable controls |
| Warning / danger | Amber / red, always with text | Signal consequential gaps or required action |
| Typography | Local system sans; local monospace for evidence | No font request, tracking or asset service |
| Type scale | 29px page title; 16px section; 14px body; 12–13px table/support text | A small, consistent hierarchy; no tiny paragraphs |
| Layout | 224px navigation; fluid content up to 1440px; optional 320px assessment | Give evidence room and decisions context |
| Spacing | 4 / 8 / 12 / 16 / 20 / 24 / 32 / 40px | Relationships through spacing before adding boxes |
| Corners / elevation | 6px controls, 8px bounded surfaces, 12px dialogs; shadow only on overlays | Avoid a grid of floating cards |
| Controls | 44px principal targets; 36px compact desktop row actions, 44px on mobile | Dense evidence without tiny controls |
| Tables | Sentence-case headers, subtle row rules, local scrolling | Compare resources across consistent columns |
| Dialogs | Native, named, Escape dismissal and opener focus return | Consequential decisions and prototype controls |

## Hierarchy and disclosure

One page heading describes the task. A short subtitle adds context rather than repeating the title. The primary action sits beside the heading for an entry page or at the end of a review form. Do not fill empty space with an extra action or invented metric. Section headings, alignment and whitespace establish groups; bordered surfaces are for tables, selected options and a focused assessment.

Use a stable, role-aware sidebar with Workspace, Collaboration and Tools groups. Captures contains Requests, Recordings, Watch live and History as contextual links. Detail routes highlight the parent section without falsely marking its link as the exact current page. Breadcrumbs provide the authorized parent. The prototype's persona/state/screen inspector lives behind **Prototype controls**, not in a permanent toolbar. Stable `UI-*` IDs stay in the catalog and inspector.

Keep essential facts visible: target, action lifecycle, current audience, workload effects/uncertainty, possible user data, effective age/deletion bounds, coverage gaps and the reason a requested action is blocked. Put optional sharing fields, source generations, exact build metadata and detailed accounting behind descriptive disclosures. On small screens, assessment follows the selection and precedes submission. Never use disclosure, hover or a tooltip as the only route to a blocking prerequisite.

Routine explanations use neutral text or a quiet inset. Amber/red notices indicate a consequential condition and a recovery path. A page-level connectivity/capacity problem is explained once; field-level problems stay at their field. Combine repeated artifact handling text into a concise persistent notice with read cutoff, deletion due and external-copy limitation. Do not claim that approved extracts are free of user data.

## Interaction and accessibility

Use semantic landmarks/headings, explicit labels, fieldset/legend for grouped choices, and aria-current for navigation/steps. Route changes focus main content; validation focuses its error summary. Inputs preserve valid values through Back and errors in production. The mockup's static fields remain documented limitations. Avoid global printable-character shortcuts and commandeering browser shortcuts.

The live viewer emphasizes its table. Display filtering updates the view directly. Start, Pause and Resume appear only in their applicable states; Close does not stop the underlying recorder. Save remains explicit. Rows expire while paused. Gaps, finite duration and handling remain visible; advanced source details expand below. Background arrivals preserve focused row controls. State changes have a polite announcement; a ticking row count is not repeatedly announced. If the focused row expires, focus moves to the stable detail area with an explanation.

Target WCAG 2.2 AA; the 44px principal-control target is an Asservat choice, not a claim that AA requires it. Test contrast, non-color cues, 320 CSS pixel reflow, zoom, focus visibility/obstruction and accessible authentication. Wide evidence tables can scroll in a labeled keyboard-focusable region; surrounding labels/actions must reflow. Mobile navigation has an explicit button, expanded state and Escape return. No sticky submission overlay obscures focused controls. Respect reduced motion and provide text/table equivalents for charts.

Component states are default, hover, focus-visible, disabled with explanation, pending, invalid, unavailable and stale. Empty/access-changed views have a safe next step. Never expose a denied resource's title/count in a breadcrumb or cached detail. Operators do not implicitly receive evidence or reviewer rights.

## Implementation and validation

Share components across all 62 cataloged routes, all personas and normal/failure states. Use local CSS and code; evidence is always escaped text. Tests cover route/state inventory, narrow layout, selected journeys, disclosures, inspector focus return, state-specific live controls and automated accessibility. The [prototype report](prototype-validation.json) records observed checks. Manual screen-reader/browser/zoom and participant task studies remain required before a production accessibility/usability claim.
