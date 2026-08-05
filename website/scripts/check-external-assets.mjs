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

// Scans the production build output for runtime references to third-party
// hosts. ASF privacy policy requires every font, script, style, and image the
// page loads to be self-hosted; this check makes a violation fail CI instead
// of shipping. Run after `pnpm build`:
//
//   node scripts/check-external-assets.mjs
//
// Only *load-bearing* references fail the check (src/href attributes, CSS
// url(...), preconnect/prefetch); plain hyperlinks to external sites are fine.

import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const websiteDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const buildDir = path.join(websiteDir, "build");

// Hosts a page may legitimately reference in load-bearing positions. Add a
// host only with a recorded ASF privacy/CSP decision.
const ALLOWED_HOSTS = new Set([
  "reqsign.opendal.apache.org",
  "www.w3.org", // xmlns in inline SVG
]);

const errors = [];

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      yield* walk(full);
    } else if (/\.(html|css|js)$/.test(entry)) {
      yield full;
    }
  }
}

// Load-bearing patterns: attributes and CSS that cause the browser to fetch.
const PATTERNS = [
  /\bsrc="(https?:\/\/[^"/]+)/g,
  /\bhref="(https?:\/\/[^"/]+)[^"]*"[^>]*\brel="(?:stylesheet|preconnect|dns-prefetch|preload|prefetch)"/g,
  /\brel="(?:stylesheet|preconnect|dns-prefetch|preload|prefetch)"[^>]*\bhref="(https?:\/\/[^"/]+)/g,
  /url\(\s*["']?(https?:\/\/[^"')/]+)/g,
  /@import\s+["'](https?:\/\/[^"'/]+)/g,
];

for (const file of walk(buildDir)) {
  const content = readFileSync(file, "utf8");
  for (const pattern of PATTERNS) {
    for (const match of content.matchAll(pattern)) {
      const host = new URL(
        match[1].startsWith("http") ? match[1] : match[2]
      ).host;
      if (!ALLOWED_HOSTS.has(host)) {
        errors.push(
          `${path.relative(buildDir, file)}: load-bearing reference to ${host}`
        );
      }
    }
  }
}

if (errors.length > 0) {
  console.error(
    `external-asset check failed with ${errors.length} finding(s):`
  );
  for (const error of [...new Set(errors)].slice(0, 50)) {
    console.error(`  - ${error}`);
  }
  process.exit(1);
}

console.log("external-asset check passed: no third-party runtime assets.");
