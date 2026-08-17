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

# Upstream Design Provenance

The Reqsign website reuses the Apache OpenDAL™ website's design skeleton.
This file records where each reused piece came from, what was intentionally
changed, and how to sync future upstream improvements.

## Source

- **Repository:** [apache/opendal](https://github.com/apache/opendal),
  `website/` directory
- **Copied at commit:** `54b8392b6e2a26a74dc037e8878729aae4d2eb40`
  (2026-07-07)
- **Last sync:** 2026-08-01 (initial import)

## Copied files and their fate

| Reqsign file | Upstream file | Relationship |
| --- | --- | --- |
| `src/css/custom.css` | `src/css/custom.css` | Skeleton kept; brand overrides (see below) |
| `src/components/landing/CodeTabs.jsx` | same path | Verbatim (mechanical rename only) |
| `src/components/landing/styles.module.css` | same path | Skeleton kept; OpenDAL-only sections (logo wall, bindings, layers) removed; Reqsign sections (flow, chooser, providers, adoption) added |
| `src/components/landing/sections.jsx` | same path | Structure reused; content and section set are Reqsign's |
| `src/components/landing/data.js` | same path | Pattern reused; all content is Reqsign's, stats derive from `data/providers.json` |
| `plugins/remark-include-code.js` | same path | Verbatim |
| `docusaurus.config.js` | same path | Pattern reused; Reqsign URLs, no blog, no community docs instance |
| `static/img/asf_logo_wide.svg` | same path | Verbatim (ASF asset) |

## Mechanical transforms (applied on every sync)

- `--odl-` → `--rs-` (CSS custom properties)
- `odl-` → `rs-` (global class names: `rs-container`, `rs-eyebrow`,
  `rs-grid-bg`, `rs-tabular`)
- `odlFade` / `odlReveal` keyframes → `rsFade` / `rsReveal`

## Intentional brand overrides (never sync these)

| Token / element | Upstream (OpenDAL) | Reqsign |
| --- | --- | --- |
| Accent palette | Precise blue `--odl-blue-*` (canonical `#1e54e0`) | Seal green `--rs-green-*` (light accent `#0a7048`, dark accent `#6fd6a8`) |
| Dark-mode primary action | Blue surface, white text | Bright green surface (`green-400`), ink text — AA requires the inversion |
| Motif | Solid level bar (from the OpenDAL wordmark) | Signature stroke: same bar skewed `−14deg` (`--rs-stroke-skew`) |
| `.odl-bar` | level rectangle | `.rs-stroke`, skewed |
| Eyebrow marker | level accent bar | skewed accent stroke |
| Logo / favicon | OpenDAL wordmark assets | Reqsign stroke + wordmark (`logo.svg`, `logo_dark.svg`, `favicon.svg`) |
| Sidebar language logos | `sidebar-lang-*` rules + `static/img/bindings/` | Removed (not applicable) |

Everything not listed above is *skeleton*: a difference found there against
upstream is drift, not identity — either sync it or record it here.

## Sync procedure

1. Diff upstream `website/` between the recorded commit and its current
   `main` for the copied files above.
2. Port skeleton changes, applying the mechanical transforms.
3. Skip any hunk touching an intentional override; if upstream restructured
   around one, adapt while preserving the Reqsign value.
4. Verify: `pnpm build`, `node scripts/validate-providers.mjs`,
   `node scripts/check-external-assets.mjs`, and a light/dark visual pass at
   375/768/1024/1440 px.
5. Update the commit hash and sync date at the top of this file.

Check monthly; sync only when upstream changes shared tokens or components.
