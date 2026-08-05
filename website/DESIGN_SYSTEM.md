<!--
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
-->

# Reqsign Design System

> **Build. Sign. Send.** An engineering-grade visual language for Apache
> OpenDAL™ Reqsign — sharing its skeleton with the OpenDAL website, carrying
> its own signature.

This document is the source of truth for Reqsign's web visual language. The
landing page (`src/pages/index.jsx`) is its first full application; docs and
providers pages inherit it through Infima variable mapping.

## 1. Skeleton and identity

The system deliberately splits into two layers with different change rules:

**Shared skeleton — inherited from the [OpenDAL Design System]
(https://github.com/apache/opendal/blob/main/website/DESIGN_SYSTEM.md), kept
in sync (see `UPSTREAM_DESIGN.md`):**

- Engineering-minimal, light-first; dark mode is a fully designed peer.
- Near-monochrome ink palette (`--rs-ink-*`).
- System sans and system mono only — zero web-font requests, zero layout
  shift, ASF-privacy-friendly. The mono stack doubles as a brand voice for
  labels, indices, and figures.
- 4px spacing rhythm; 1200px container with responsive gutters.
- Hairline structure: 1px borders, 1px grid gaps, restrained radius/shadow.
- Code-first, content-first layouts.
- CSS-only progressive motion honoring `prefers-reduced-motion`.

**Reqsign identity — intentional divergence, never synced from upstream:**

- **Seal green** (`--rs-green-*`) replaces OpenDAL's precise blue as the
  single accent. Green-700 `#0a7048` is the light-mode accent (≥ 4.5:1 on
  white); green-300 `#6fd6a8` is the dark-mode accent. In dark mode, primary
  actions invert to a bright-green surface with ink text — white-on-green
  cannot reach AA there.
- **The signature stroke** replaces OpenDAL's solid bar: the same solid
  quadrilateral, slanted by `--rs-stroke-skew` (−14°). Where the OpenDAL bar
  sits level like a storage layer, the Reqsign stroke leans forward like a
  pen closing a signature. Used in the eyebrow marker (`.rs-eyebrow::before`),
  the standalone `.rs-stroke`, the logo, and the favicon.
- **Wordmark**: the stroke plus "Reqsign" in the system stack
  (`static/img/logo.svg`, `logo_dark.svg`). The full `Apache OpenDAL
  Reqsign™` name appears in the page title, hero eyebrow, and footer
  attribution rather than inside the mark.

## 2. Where the system lives

| Concern | Location |
| --- | --- |
| Tokens + Infima mapping + motif | `src/css/custom.css` |
| Landing sections | `src/components/landing/sections.jsx` |
| Landing content model | `src/components/landing/data.js` |
| Code window / provider tabs | `src/components/landing/CodeTabs.jsx` |
| Landing styles | `src/components/landing/styles.module.css` |
| Provider facts &amp; matrix (embedded in docs) | `src/components/providers/` |

## 3. Token layers

1. **Primitives** — raw values: `--rs-ink-*`, `--rs-green-*`, type scale,
   spacing, radius, motion.
2. **Semantic** — theme-aware roles: `--rs-bg`, `--rs-fg`, `--rs-accent`,
   `--rs-action-*`, `--rs-stroke`. Components consume these, never
   primitives.
3. **Infima projection** — semantic tokens mapped onto `--ifm-*` so docs,
   navbar, and footer inherit the system without per-page styling.

The accent is replaceable at exactly one place (the semantic layer); nothing
downstream hard-codes a color.

## 4. Rules that keep it coherent

- One accent. Green marks interaction and emphasis; everything else is ink.
- The stroke stays sharp (no radius) and always skewed by the shared token.
- Mono for labels/metrics/eyebrows; sans for prose. Never mix per element.
- Light and dark ship together: every surface, chip, and code window is
  designed in both before landing.
- Accessibility gates: WCAG 2.1 AA contrast in both modes,
  `:focus-visible` outlines, keyboard-reachable tabs and navigation,
  `prefers-reduced-motion` honored by every animation.
- No third-party runtime assets — fonts, scripts, styles, and images are
  self-hosted (`scripts/check-external-assets.mjs` enforces this after every
  build).

## 5. Content rules

- Capability numbers and provider lists derive from `data/providers.json`;
  the page must not hand-write claims the catalog cannot back.
- Code shown on the landing page mirrors compiled examples
  (`reqsign/examples/`) or in-tree doc tests; docs snippets include real
  files via `remark-include-code`.
- Copy states what is verified, never "every cloud".
