/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Validates data/providers.json against the Cargo workspace so provider
// capability claims cannot drift from the code. Run from website/:
//
//   node scripts/validate-providers.mjs
//
// Checks:
//   - every catalog crate exists in `cargo metadata`;
//   - every facade feature exists in the reqsign facade crate;
//   - every workspace crate is either claimed by a provider or listed as an
//     internal crate (new service crates must be cataloged);
//   - provider ids are unique and URL-safe;
//   - every source_ref path exists in the repository;
//   - last_verified dates parse and are not in the future.

import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const websiteDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const repoRoot = path.dirname(websiteDir);

const catalog = JSON.parse(
  readFileSync(path.join(websiteDir, "data", "providers.json"), "utf8")
);

const metadata = JSON.parse(
  execSync("cargo metadata --format-version 1 --no-deps", {
    cwd: repoRoot,
    maxBuffer: 64 * 1024 * 1024,
  }).toString()
);

const workspaceCrates = new Map(
  metadata.packages.map((p) => [p.name, p])
);

const errors = [];

// --- crates exist ----------------------------------------------------------
const claimedCrates = new Set();
for (const provider of catalog.providers) {
  for (const crate of provider.crates) {
    claimedCrates.add(crate);
    if (!workspaceCrates.has(crate)) {
      errors.push(`provider ${provider.id}: crate ${crate} not in workspace`);
    }
  }
}
for (const internal of catalog.internal_crates) {
  claimedCrates.add(internal.name);
  if (!workspaceCrates.has(internal.name)) {
    errors.push(`internal crate ${internal.name} not in workspace`);
  }
}

// --- every workspace crate is claimed --------------------------------------
for (const name of workspaceCrates.keys()) {
  if (!claimedCrates.has(name)) {
    errors.push(
      `workspace crate ${name} is neither claimed by a provider nor listed in internal_crates`
    );
  }
}

// --- facade features exist --------------------------------------------------
const facade = workspaceCrates.get("reqsign");
const facadeFeatures = facade ? new Set(Object.keys(facade.features)) : new Set();
for (const provider of catalog.providers) {
  for (const feature of provider.facade_features) {
    if (!facadeFeatures.has(feature.name)) {
      errors.push(
        `provider ${provider.id}: facade feature ${feature.name} not found in reqsign crate`
      );
    }
  }
}

// --- ids unique and URL-safe ------------------------------------------------
const seenIds = new Set();
for (const provider of catalog.providers) {
  if (!/^[a-z0-9-]+$/.test(provider.id)) {
    errors.push(`provider id ${provider.id} is not URL-safe`);
  }
  if (seenIds.has(provider.id)) {
    errors.push(`duplicate provider id ${provider.id}`);
  }
  seenIds.add(provider.id);
}

// --- every provider has a docs page -----------------------------------------
for (const provider of catalog.providers) {
  const docPage = path.join(
    websiteDir,
    "docs",
    "providers",
    `${provider.id}.mdx`
  );
  if (!existsSync(docPage)) {
    errors.push(
      `provider ${provider.id}: missing docs page docs/providers/${provider.id}.mdx`
    );
  }
}

// --- source refs exist ------------------------------------------------------
function checkRef(owner, ref) {
  if (!existsSync(path.join(repoRoot, ref))) {
    errors.push(`${owner}: source ref ${ref} does not exist`);
  }
}
for (const provider of catalog.providers) {
  for (const ref of provider.source_refs) checkRef(`provider ${provider.id}`, ref);
  for (const grant of provider.credential_granting) {
    for (const ref of grant.source_refs) {
      checkRef(`provider ${provider.id} granting ${grant.name}`, ref);
    }
  }
  for (const test of provider.integration_tests.refs ?? []) {
    checkRef(`provider ${provider.id} tests`, test);
  }
}

// --- credential sources carry verified type names ---------------------------
for (const provider of catalog.providers) {
  if (!workspaceCrates.has(provider.credential_provider_crate)) {
    errors.push(
      `provider ${provider.id}: credential_provider_crate ${provider.credential_provider_crate} not in workspace`
    );
  }
  for (const s of [
    ...provider.credential_sources,
    ...(provider.explicit_sources ?? []),
  ]) {
    if (!s.provider || !/^[A-Za-z0-9]+$/.test(s.provider)) {
      errors.push(
        `provider ${provider.id}: credential source ${s.id} lacks a valid Rust provider type name`
      );
    }
  }
}

// --- required fields & dates ------------------------------------------------
const REQUIRED = [
  "id",
  "display_name",
  "family",
  "blurb",
  "service_scope",
  "signing_schemes",
  "crates",
  "facade_features",
  "default_signer",
  "credential_sources",
  "request_auth",
  "credential_granting",
  "wasm",
  "integration_tests",
  "source_refs",
  "last_verified",
];
// Compare in local time: last_verified is stamped by maintainers in their
// own timezone, so a UTC comparison would reject same-day entries.
const now = new Date();
const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
for (const provider of catalog.providers) {
  for (const field of REQUIRED) {
    if (!(field in provider)) {
      errors.push(`provider ${provider.id}: missing field ${field}`);
    }
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(provider.last_verified)) {
    errors.push(`provider ${provider.id}: last_verified is not YYYY-MM-DD`);
  } else if (provider.last_verified > today) {
    errors.push(`provider ${provider.id}: last_verified is in the future`);
  }
}

if (errors.length > 0) {
  console.error(`providers.json validation failed with ${errors.length} error(s):`);
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}

console.log(
  `providers.json validated: ${catalog.providers.length} providers, ` +
    `${catalog.internal_crates.length} internal crates, workspace fully claimed.`
);
