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

import React, { useState } from "react";
import Link from "@docusaurus/Link";
import CodeBlock from "@theme/CodeBlock";
import CodeTabs from "./CodeTabs";
import styles from "./styles.module.css";
import {
  REPO_URL,
  DOCS_URL,
  PROVIDERS_URL,
  DISCORD_URL,
  heroStats,
  codeSamples,
  valueProps,
  howItWorks,
  capabilityThemes,
  providers,
  adoption,
} from "./data";

export function Hero() {
  return (
    <header className={styles.hero}>
      <div className={`${styles.heroGrid} rs-grid-bg`} aria-hidden="true" />
      <div className="rs-container">
        <div className={styles.heroInner}>
          <div>
            <span className="rs-eyebrow">
              Apache OpenDAL™ Reqsign — Request Signing
            </span>
            <h1 className={styles.heroTitle}>
              Build. <span className={styles.heroTitleAccent}>Sign.</span> Send.
            </h1>
            <p className={styles.heroLede}>
              Sign HTTP requests, load cloud credentials, and grant scoped
              access — without pulling in a full vendor SDK.
            </p>
            <div className={styles.heroActions}>
              <Link
                className={`${styles.btn} ${styles.btnPrimary}`}
                to={DOCS_URL}
              >
                Get started <span className={styles.btnArrow}>→</span>
              </Link>
              <Link
                className={`${styles.btn} ${styles.btnSecondary}`}
                to={REPO_URL}
              >
                View on GitHub
              </Link>
            </div>
            <div className={styles.heroStats}>
              {heroStats.map((stat) => (
                <div className={styles.heroStat} key={stat.label}>
                  <span className={styles.heroStatValue}>{stat.value}</span>
                  <span className={styles.heroStatLabel}>{stat.label}</span>
                </div>
              ))}
            </div>
          </div>
          <div className={styles.heroAside}>
            <CodeTabs samples={codeSamples} title="quickstart" equalize />
          </div>
        </div>
      </div>
    </header>
  );
}

export function Adoption() {
  return (
    <section className={`${styles.section} ${styles.sectionSubtle}`}>
      <div className="rs-container">
        <div className={styles.adoptionStrip}>
          <span className="rs-eyebrow">Proven in production</span>
          <p className={styles.adoptionClaim}>
            <Link to={adoption.href} className={styles.adoptionName}>
              {adoption.name}
            </Link>{" "}
            {adoption.claim}
          </p>
        </div>
      </div>
    </section>
  );
}

export function ValueProps() {
  return (
    <section className={styles.section}>
      <div className="rs-container">
        <div className={styles.sectionHead}>
          <span className="rs-eyebrow">Why Reqsign</span>
          <h2 className={styles.sectionTitle}>
            The signing layer, and nothing else.
          </h2>
          <p className={styles.sectionLede}>
            Reqsign keeps each provider&apos;s protocol explicit while sharing
            one composition pattern — so your client stays yours.
          </p>
        </div>
        <div className={`${styles.valueGrid} ${styles.reveal}`}>
          {valueProps.map((v) => (
            <article className={styles.valueCard} key={v.index}>
              <span className={styles.valueIndex}>{v.index}</span>
              <h3 className={styles.valueCardTitle}>{v.title}</h3>
              <p className={styles.valueCardBody}>{v.body}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

export function HowItWorks() {
  return (
    <section className={`${styles.section} ${styles.sectionSubtle}`}>
      <div className="rs-container">
        <div className={styles.sectionHead}>
          <span className="rs-eyebrow">How it works</span>
          <h2 className={styles.sectionTitle}>
            Three steps. Your client stays in charge.
          </h2>
        </div>
        <ol className={`${styles.flowGrid} ${styles.reveal}`}>
          {howItWorks.map((step, i) => (
            <li className={styles.flowStep} key={step.index}>
              <span className={styles.flowIndex}>{step.index}</span>
              <h3 className={styles.flowTitle}>{step.title}</h3>
              <p className={styles.flowBody}>{step.body}</p>
              {i < howItWorks.length - 1 && (
                <span className={styles.flowArrow} aria-hidden="true">
                  →
                </span>
              )}
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

export function Capabilities() {
  const [active, setActive] = useState(capabilityThemes[0]);
  return (
    <section className={styles.section}>
      <div className="rs-container">
        <div className={styles.sectionHead}>
          <span className="rs-eyebrow">Capabilities</span>
          <h2 className={styles.sectionTitle}>
            From default chains to downscoped grants.
          </h2>
          <p className={styles.sectionLede}>
            Start with one call, then take over any piece: credentials, runtime,
            query authentication, or the grant that scopes access before a
            request is ever signed.
          </p>
        </div>
        <div className={styles.capabilityExplorer}>
          <ul className={styles.capabilityNav}>
            {capabilityThemes.map((theme) => {
              const selected = active.title === theme.title;
              return (
                <li key={theme.title}>
                  <Link
                    className={`${styles.capabilityItem} ${
                      selected ? styles.capabilityItemActive : ""
                    }`}
                    to={theme.doc}
                    aria-current={selected ? "true" : undefined}
                    onMouseEnter={() => setActive(theme)}
                    onFocus={() => setActive(theme)}
                  >
                    <span className={styles.capabilityText}>
                      <span className={styles.capabilityItemTitle}>
                        {theme.title}
                      </span>
                      <span className={styles.capabilityItemBlurb}>
                        {theme.blurb}
                      </span>
                    </span>
                    <span className={styles.capabilityArrow} aria-hidden="true">
                      ↗
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
          <div className={styles.capabilityPreview}>
            <div className={styles.codeWindow}>
              <div className={styles.windowBar}>
                <div className={styles.windowDots} aria-hidden="true">
                  <span />
                  <span />
                  <span />
                </div>
                <span className={styles.windowTitle}>{active.title}</span>
              </div>
              <div className={`${styles.codeBody} ${styles.capabilityCodeBody}`}>
                <div className={styles.capabilityCodeFade} key={active.title}>
                  <CodeBlock language="rust">{active.code}</CodeBlock>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export function Providers() {
  return (
    <section className={`${styles.section} ${styles.sectionSubtle}`}>
      <div className="rs-container">
        <div className={styles.sectionHead}>
          <span className="rs-eyebrow">Providers</span>
          <h2 className={styles.sectionTitle}>
            {providers.length} providers. Explicit schemes.
          </h2>
          <p className={styles.sectionLede}>
            Signers and credentials stay service-specific on purpose — the
            protocol differences are real, and hiding them breaks correctness.
            What Reqsign shares is the composition pattern.
          </p>
        </div>
        <div className={`${styles.providerGrid} ${styles.reveal}`}>
          {providers.map((p) => (
            <Link
              className={styles.providerCard}
              to={`/docs/providers/${p.id}/`}
              key={p.id}
            >
              <span className={styles.providerName}>{p.display_name}</span>
              <span className={styles.providerSchemes}>
                {p.signing_schemes.join(" · ")}
              </span>
            </Link>
          ))}
        </div>
        <div className={styles.providersFoot}>
          <Link
            className={`${styles.btn} ${styles.btnSecondary}`}
            to={PROVIDERS_URL}
          >
            Read the provider matrix <span className={styles.btnArrow}>→</span>
          </Link>
        </div>
      </div>
    </section>
  );
}

export function FinalCta() {
  return (
    <section className={`${styles.section} ${styles.sectionSubtle}`}>
      <div className="rs-container">
        <div className={styles.finalCta}>
          <div className={`${styles.finalCtaInner} ${styles.finalCenter}`}>
            <span className={`rs-eyebrow ${styles.finalEyebrow}`}>
              Start signing
            </span>
            <h2 className={styles.finalCtaTitle}>
              Ship your own client, not an SDK.
            </h2>
            <p className={styles.finalCtaLede}>
              Five minutes to a signed request — with credentials, presigning,
              and scoped grants when you need them.
            </p>
            <div className={styles.finalCtaActions}>
              <Link
                className={`${styles.btn} ${styles.btnPrimary}`}
                to={DOCS_URL}
              >
                Sign your first request <span className={styles.btnArrow}>→</span>
              </Link>
              <Link
                className={`${styles.btn} ${styles.btnSecondary}`}
                to={PROVIDERS_URL}
              >
                Read the provider matrix
              </Link>
              <Link
                className={`${styles.btn} ${styles.btnSecondary}`}
                to={DISCORD_URL}
              >
                Join the OpenDAL community
              </Link>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
