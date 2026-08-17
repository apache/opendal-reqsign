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

// The header of a provider docs page: one sentence of scope and one row of
// capability facts, rendered from data/providers.json. The quickstart that
// follows lives in the surrounding MDX; the credential/granting details are
// rendered by ProviderDetails at the bottom of the page.

import React from "react";
import Link from "@docusaurus/Link";
import catalog from "@site/data/providers.json";
import styles from "./styles.module.css";

function Flag({ on, label }) {
  return (
    <span className={on ? styles.flagOn : styles.flagOff}>
      {on ? "✓" : "—"} {label}
    </span>
  );
}

export default function ProviderFacts({ id }) {
  const p = catalog.providers.find((provider) => provider.id === id);
  if (!p) {
    throw new Error(`ProviderFacts: unknown provider id "${id}"`);
  }

  return (
    <>
      <p className={styles.scopeLede}>{p.service_scope}</p>

      <div className={styles.factsBar}>
        {p.signing_schemes.map((s) => (
          <span className={styles.schemeChip} key={s}>
            {s}
          </span>
        ))}
        <span className={styles.factsDivider} aria-hidden="true" />
        <Flag on={p.request_auth.header} label="header signing" />
        <Flag on={p.request_auth.query} label="query / presign" />
        <Flag on={p.wasm.supported} label="WASM" />
        <Link
          className={styles.factsDocsLink}
          to={`https://docs.rs/${p.crates[0]}`}
        >
          docs.rs/{p.crates[0]} ↗
        </Link>
      </div>

      {p.request_auth.notes && (
        <p className={styles.factsNote}>{p.request_auth.notes}</p>
      )}
    </>
  );
}
