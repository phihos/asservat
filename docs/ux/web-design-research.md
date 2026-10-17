# Web console design research and application

Researched 2026-10-09 for the Asservat console. This review uses current primary design-system guidance, accessibility requirements, and a documented product redesign. It does not claim there is one empirically established “best” contemporary style. Asservat's preference for a clean, minimalist interface is a product decision; usefulness must still be tested with maintainers and operators.

## Evidence and decisions

| Primary source | What it supports | Asservat decision |
| --- | --- | --- |
| [Carbon data tables](https://www.carbondesignsystem.com/building-blocks/core/components/data-table/guidelines), current guidance checked October 2026 | Tables organize comparable resources; put search and actions near the data. Expanded rows or separate views accommodate detail. Give dense tables sufficient width. | Cases, profiles, sources and cluster health use broad tables. Avoid enclosing every cell or table in another decorative card. Keep row actions recognizable and keyboard reachable. |
| [Carbon UI shell](https://www.carbondesignsystem.com/building-blocks/core/components/ui-shell-left-panel/guidelines), current guidance checked October 2026 | Separate application navigation from content; avoid excessive navigation depth. | Stable, role-aware sidebar with section-level destinations. Capture requests, recordings, live sources and history share a contextual navigation row. Detail pages retain a parent link. |
| [GOV.UK details](https://design-system.service.gov.uk/components/details/) | Reveal supplementary information on demand, but keep information most users need visible. | Collapse source epochs, accounting details and optional sharing settings. Do not collapse the only impact, audience, deletion or blocked-action explanation. |
| [GOV.UK buttons](https://design-system.service.gov.uk/components/button/) | Use action-specific sentence-case labels; avoid multiple competing primary actions. | A single emphasized next step in each decision context. Collection review submits once. Start/Pause/Resume are state-specific; irrelevant alternatives disappear. |
| [GOV.UK warning text](https://design-system.service.gov.uk/components/warning-text/) | Warnings are for consequential information. | Reserve amber/red emphasis for loss, missing authority, overdue cleanup or intrusive effects. Routine provenance and general help use neutral text and details. |
| [Linear's redesign account](https://linear.app/now/how-we-redesigned-the-linear-ui), **28 March 2024** | The product team describes reducing visual noise through alignment and a clearer hierarchy of chrome, tabs and panels. This is a primary account of design practice, not a controlled usability study or a 2026 launch. | Use a light neutral shell, aligned controls, a restrained accent and consistent spacing. Borrow the hierarchy principle, not proprietary branding or a framework. |
| [WCAG 2.2 target size](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html) | AA defines 24×24 CSS pixels or qualifying exceptions; larger controls can help users. | Choose 44px principal buttons and form controls. Compact desktop row actions stay at least 36px, with larger mobile targets. Minimalism must not shrink the usable target. |
| [WCAG reflow](https://www.w3.org/WAI/WCAG22/Understanding/reflow.html) | Content must reflow at the equivalent of 320 CSS pixels, with exceptions for content requiring two-dimensional layout. | Stack review columns, keep actions in normal flow, and contain wide evidence tables in labeled keyboard-scrollable regions. Check actual 320px layouts instead of treating desktop scaling as a mobile design. |
| [WCAG focus not obscured](https://www.w3.org/WAI/WCAG22/Understanding/focus-not-obscured-minimum.html) and [WAI modal dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/) | Keyboard focus must remain usable; modal dialogs need names, contained focus, dismissal and appropriate return. | Native dialogs for the prototype inspector and consequential actions. Visible keyboard focus, no sticky submission overlay, and no focus replacement on each live row arrival. |

The original [UX/interface research](research.md) continues to govern transport, authorization and application-boundary choices. This review does not change the MCP protocol, domain ownership or collector architecture.

## Applied overhaul

1. Remove the permanent persona/screen/state toolbar. A small, labeled Prototype controls button opens a separate native dialog. Keep a visible synthetic-preview label and document that this inspector is not shipped product UI.
2. Replace the dark, visually heavy sidebar and many boxed panels with a quiet light shell, section navigation, plain content sections and a small number of meaningful boundaries. Accent color identifies actions and selection; state always has words.
3. Remove `UI-*` identifiers from page headings. Keep those stable identifiers in the inventory and prototype inspector. Write page descriptions for the task rather than restating the architecture.
4. Make overview and administration answer what needs attention. Use comparable case/cluster rows and concise recovery links; avoid adding a metric merely to fill a dashboard tile.
5. Keep composition and review predictable: target, evidence, review. Use a readable summary with impact and handling beside it on desktop and before submission on narrow screens. Optional sharing is a named disclosure; audience remains visible.
6. Let live observations occupy the main surface. Use direct display filtering, finite status, state-specific playback controls, and an explicit save path. Keep gaps and user-data handling visible. Source internals and detailed budgets can be expanded. Announce state changes rather than every incoming row.
7. Apply shared typography, field, table, dialog, warning and empty-state components to every inventoried screen, including recipient, approver, administrative and failure views. Preserve all 62 routes and existing authorization boundaries.

This visual overhaul introduced no component library, remote font, infinite stream, implicit collection or AI feature into the prototype. The later accepted technology decision ADR-046 selects React/TypeScript and unstyled React Aria primitives for production, with compiled assets served by Go; the visual guidance and existing prototype remain applicable.

## Deliberate limits and evaluation

A calmer appearance is not evidence of reduced task time. The browser gate checks the synthetic prototype's routes, seven states, interaction examples, responsive overflow and automated accessibility rules. It does not qualify real authorization, prove WCAG conformance, validate every screen reader or measure usability.

Before release, test these tasks with maintainers and operators: find the failing workload; choose the smallest useful evidence set; locate a live source through the Captures section; distinguish pause from save; explain who can read a capture; revoke a share; resolve an overdue deletion. Observe wrong turns, unnoticed prerequisites, completion time and comprehension of deadlines. In particular, test discoverability after consolidating navigation and whether technical disclosures hide needed diagnostic context. Use participant results to adjust the design rather than adding speculative controls now.
