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

// The provider capability matrix, rendered from data/providers.json on the
// docs providers index. A table scales with the catalog: new providers become
// new rows, and every cell traces back to the machine-checked catalog.

import React from "react";
import Link from "@docusaurus/Link";
import catalog from "@site/data/providers.json";
import styles from "./styles.module.css";

function Mark({ on }) {
  return (
    <span className={on ? styles.flagOn : styles.flagOff}>
      {on ? "✓" : "—"}
    </span>
  );
}

export default function ProvidersMatrix() {
  return (
    <>
      <div className={styles.matrixWrap}>
        <table className={styles.matrix}>
          <thead>
            <tr>
              <th>Provider</th>
              <th>Signing schemes</th>
              <th>Header</th>
              <th>Query / presign</th>
              <th>Granting</th>
              <th>WASM</th>
            </tr>
          </thead>
          <tbody>
            {catalog.providers.map((p) => (
              <tr key={p.id}>
                <td>
                  <Link to={`/docs/providers/${p.id}/`}>{p.display_name}</Link>
                </td>
                <td className={styles.matrixSchemes}>
                  {p.signing_schemes.join(", ")}
                </td>
                <td>
                  <Mark on={p.request_auth.header} />
                </td>
                <td>
                  <Mark on={p.request_auth.query} />
                </td>
                <td>
                  {p.credential_granting.length > 0 ? (
                    <span className={styles.flagOn}>
                      ✓ {p.credential_granting.length}
                    </span>
                  ) : (
                    <span className={styles.flagOff}>—</span>
                  )}
                </td>
                <td>
                  <Mark on={p.wasm.supported} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className={styles.verifiedNote}>
        Capability data last verified against{" "}
        <code>apache/opendal-reqsign@{catalog.verified_commit}</code>; CI fails
        when this matrix drifts from the workspace. Found a mismatch?{" "}
        <Link to="https://github.com/apache/opendal-reqsign/issues">
          Open an issue.
        </Link>
      </p>
    </>
  );
}
