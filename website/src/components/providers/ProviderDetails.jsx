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

// The data-driven bottom half of a provider docs page, rendered from
// data/providers.json with plain docs typography. Two credential views serve
// two different questions: the default chain answers "what happens when I
// call default_signer?", the full provider list answers "what can I compose
// myself?". Granting renders only when the provider has any operation.

import React from "react";
import Link from "@docusaurus/Link";
import catalog from "@site/data/providers.json";

export default function ProviderDetails({ id }) {
  const p = catalog.providers.find((provider) => provider.id === id);
  if (!p) {
    throw new Error(`ProviderDetails: unknown provider id "${id}"`);
  }
  const allProviders = [...p.credential_sources, ...(p.explicit_sources ?? [])];
  // rustdoc generates struct pages only in the defining crate, so type links
  // target credential_provider_crate rather than the facade-facing crate.
  const docsCrate = p.credential_provider_crate;
  const docsPath = docsCrate.replace(/-/g, "_");
  const typeUrl = (type) =>
    `https://docs.rs/${docsCrate}/latest/${docsPath}/struct.${type}.html`;

  return (
    <>
      <h2>Credentials</h2>

      <h3>Default credential chain</h3>
      <p>
        The default signer tries these sources in order and uses the first one
        that yields a credential — no configuration needed when any of them is
        present:
      </p>
      <ol>
        {p.credential_sources.map((s) => (
          <li key={s.id}>{s.label}</li>
        ))}
      </ol>

      <h3>All credential providers</h3>
      <p>
        Every <code>ProvideCredential</code> implementation this provider
        ships. Construct any of them directly, reorder them, or compose them
        into your own chain — see{" "}
        <Link to="/docs/guides/credentials/">Loading credentials</Link>:
      </p>
      <ul>
        {allProviders.map((s) => (
          <li key={s.id}>
            <Link to={typeUrl(s.provider)}>
              <code>{s.provider}</code>
            </Link>{" "}
            — {s.label}
          </li>
        ))}
      </ul>

      {p.credential_granting.length > 0 && (
        <>
          <h2>Credential granting</h2>
          <p>
            This provider can exchange credentials for downscoped ones before
            any request is signed — see{" "}
            <Link to="/docs/guides/granting/">Granting scoped access</Link>:
          </p>
          <ul>
            {p.credential_granting.map((g) => (
              <li key={g.name}>
                <strong>{g.name}</strong> — {g.mechanism}
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}
