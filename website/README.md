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

# Reqsign Website

The Apache OpenDAL™ Reqsign website — a [Docusaurus](https://docusaurus.io/)
site targeting `https://reqsign.opendal.apache.org/`.

## Development

```bash
pnpm install
pnpm start        # dev server
pnpm build        # production build into build/
pnpm serve        # serve the production build locally
```

Requires Node ≥ 24.17 and pnpm 11 (`corepack enable`).

## Checks

```bash
pnpm validate-providers      # catalog ↔ cargo metadata consistency
pnpm build                   # also fails on broken internal links
pnpm check-external-assets   # no third-party runtime assets (run after build)
```

## Layout

| Path | Purpose |
| --- | --- |
| `data/providers.json` | Provider capability catalog — the single source of truth for every capability claim; validated in CI |
| `docs/` | Concept, guide, contract, compatibility, and provider documentation |
| `docs/providers/` | One page per provider: capability facts render from the catalog via `ProviderFacts`; provider-specific prose lives in the MDX. The validator requires a page per catalog entry |
| `src/pages/` | Landing page, `/download`, `/community` |
| `src/components/landing/` | Landing sections and content model |
| `src/components/providers/` | `ProviderFacts` and `ProvidersMatrix`, the catalog-rendering components embedded in docs pages |
| `plugins/remark-include-code.js` | Includes real repository files into docs code blocks |
| `scripts/` | Catalog validator and external-asset check |
| `DESIGN_SYSTEM.md` | Visual language: shared skeleton + Reqsign identity |
| `UPSTREAM_DESIGN.md` | Provenance and sync procedure for design reused from the OpenDAL website |

## Editing rules

- **Provider capabilities** change in `data/providers.json` (with source
  refs), never directly in page copy. Run the validator.
- **Code snippets** in docs come from compiled sources via
  ` ```rust file=path/to/file.rs ` fences where possible; landing snippets
  mirror `reqsign/examples/` and in-tree doc tests.
- **Design changes** to shared-skeleton styles should go through the sync
  procedure in `UPSTREAM_DESIGN.md`; Reqsign-identity overrides (accent,
  stroke motif, wordmark) are documented there and never synced.

## Environment variables

| Variable | Effect |
| --- | --- |
| `REQSIGN_WEBSITE_URL` | Overrides the canonical site URL |
| `REQSIGN_WEBSITE_BASE_URL` | Overrides `baseUrl` (fallback deployments) |
| `REQSIGN_WEBSITE_STAGING=true` | Marks the build as staging: sets `noIndex` |
