---
version: alpha
name: QuantumTrace
description: Cryptographic inventory using the imported Lovable cream and charcoal workspace.
colors:
  background: "oklch(0.975 0.013 91)"
  primary: "oklch(0.26 0.018 85)"
  sidebar: "oklch(0.215 0.008 85)"
  critical: "oklch(0.59 0.15 28)"
  medium: "oklch(0.63 0.115 76)"
  safe: "oklch(0.53 0.076 158)"
typography:
  sans:
    fontFamily: "DM Sans, sans-serif"
  mono:
    fontFamily: "IBM Plex Mono, monospace"
rounded:
  DEFAULT: "0.5rem"
  panel: "6px"
spacing:
  page-max: "1480px"
  sidebar-width: "232px"
components:
  button: {}
  dialog: {}
  table: {}
  input: {}
---

# QuantumTrace design

## Product and identity
Security engineers inspect evidence and prioritise migration. Preserve the actual
Lovable export's cream canvas, charcoal sidebar, khaki details, geometric mark,
compact data tables and thin panel borders. This is a product dashboard in English;
there is no market-specific locale requirement. Dates explicitly use UTC.

## Canonical tokens and runtime mapping
`src/styles.css` is the canonical token source. This document mirrors its intent;
`:root` values feed Tailwind through `@theme inline`, then shared UI primitives and
the workspace. Keep these references consistent when changing the palette.
DM Sans is the body/display family; IBM Plex Mono identifies technical evidence.
Fallback system fonts remain usable offline. No dark theme is offered.

## Layout and components
The imported shell owns all four routes. Its sidebar collapses below 760px;
tables scroll horizontally within the panel. Buttons and dialogs use existing
Radix-backed primitives. The mobile navigation uses the existing Sheet primitive.
Errors use persistent inline alerts; loading keeps the previous report visible.
The global stylesheet owns scrollbars, focus states and reduced motion.
Risk always includes a text label. Quantum safety and classical status remain
separate. Unencrypted findings must never receive the safe badge.

## Verification
Typecheck, adapter/provider tests, route tests, production build and browser checks
cover loading, empty, error, demo, filtering, pagination, evidence and exports.
