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

// @ts-check

const semver = require("semver");
const exec = require("child_process").execSync;

const { themes } = require("prism-react-renderer");
const repoAddress = "https://github.com/apache/opendal-reqsign";

// The canonical hostname is pending ASF Infra approval; keep url/baseUrl
// configurable so staging and the documented fallbacks need no code change.
const url = process.env.REQSIGN_WEBSITE_URL
  ? process.env.REQSIGN_WEBSITE_URL
  : "https://reqsign.opendal.apache.org";
const baseUrl = process.env.REQSIGN_WEBSITE_BASE_URL
  ? process.env.REQSIGN_WEBSITE_BASE_URL
  : "/";
const websiteStaging = process.env.REQSIGN_WEBSITE_STAGING
  ? process.env.REQSIGN_WEBSITE_STAGING === "true"
  : false;

// Resolve the released facade version from Git tags so installation snippets
// never hard-code a stale version.
const websiteVersion = (function () {
  try {
    const refName = exec(
      "git describe --tags --abbrev=0 --match 'v*' --exclude '*rc*'"
    ).toString();
    const version = semver.parse(refName.trim().replace(/^v/, ""), {}, true);
    return `${version.major}.${version.minor}.${version.patch}`;
  } catch (error) {
    console.warn("Failed to get version from Git, using default '0.0.0'");
    return "0.0.0";
  }
})();

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: "Apache OpenDAL™ Reqsign",
  tagline:
    "Sign HTTP requests, load cloud credentials, and grant scoped access without pulling in a full vendor SDK.",
  favicon: "img/favicon.svg",

  customFields: {
    isStaging: websiteStaging,
    version: websiteVersion,
  },

  url,
  baseUrl,

  // Staging deployments must never be indexed by search engines.
  noIndex: websiteStaging,

  trailingSlash: true,

  onBrokenLinks: "throw",
  markdown: {
    format: "detect",
    hooks: {
      onBrokenMarkdownLinks: "throw",
    },
  },

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  future: {
    faster: {
      rspackBundler: true,
      rspackPersistentCache: true,
    },
  },

  presets: [
    [
      "@docusaurus/preset-classic",
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: "docs",
          sidebarPath: require.resolve("./docs/sidebars.js"),
          editUrl: "https://github.com/apache/opendal-reqsign/tree/main/website/",
          showLastUpdateAuthor: true,
          showLastUpdateTime: true,
          remarkPlugins: [require("./plugins/remark-include-code")],
        },
        // Announcements and long-form posts live on the OpenDAL blog; Reqsign
        // does not run its own.
        blog: false,
        theme: {
          customCss: require.resolve("./src/css/custom.css"),
        },
        sitemap: {
          changefreq: "daily",
          priority: 0.5,
          ignorePatterns: ["/tags/**"],
          filename: "sitemap.xml",
        },
      }),
    ],
  ],

  plugins: [
    require.resolve("docusaurus-lunr-search"),
    [
      "docusaurus-plugin-llms-builder",
      /** @type {import("docusaurus-plugin-llms-builder").PluginOptions} */
      ({
        version: websiteVersion,
        llmConfigs: [
          {
            title: "Apache OpenDAL™ Reqsign: Build. Sign. Send.",
            description:
              "Reqsign signs HTTP requests and loads cloud credentials for AWS, Azure, Google, Aliyun, Huawei Cloud, Oracle, Tencent, and Volcengine services without pulling in full vendor SDKs.",
            summary:
              "Reqsign keeps explicit per-provider signing protocols while sharing one composition pattern: build the request, load or grant credentials, sign, then send with your own HTTP client.",
            generateLLMsTxt: true,
            generateLLMsFullTxt: true,
            sessions: [
              {
                type: "docs",
                docsDir: "docs",
                sessionName: "Docs",
                sitemap: "sitemap.xml",
                patterns: {
                  orderPatterns: (a, b) => {
                    const aPath = new URL(a).pathname;
                    const bPath = new URL(b).pathname;

                    const aSegments = aPath.split("/").filter(Boolean);
                    const bSegments = bPath.split("/").filter(Boolean);

                    if (aSegments.length !== bSegments.length) {
                      return aSegments.length - bSegments.length;
                    }

                    return a.localeCompare(b);
                  },
                },
              },
            ],
          },
        ],
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        defaultMode: "light",
        disableSwitch: false,
        respectPrefersColorScheme: true,
      },
      navbar: {
        logo: {
          alt: "Apache OpenDAL Reqsign",
          src: "img/logo.svg",
          srcDark: "img/logo_dark.svg",
          href: "/",
          target: "_self",
          height: 32,
        },
        items: [
          {
            type: "doc",
            docId: "what-is-reqsign",
            position: "right",
            label: "Docs",
          },
          {
            to: "/docs/providers/",
            label: "Providers",
            position: "right",
          },
          {
            to: "/download",
            label: "Download",
            position: "right",
          },
          {
            to: "/community",
            label: "Community",
            position: "right",
          },
          {
            type: "dropdown",
            label: "ASF",
            position: "right",
            items: [
              {
                label: "Foundation",
                to: "https://www.apache.org/",
              },
              {
                label: "License",
                to: "https://www.apache.org/licenses/",
              },
              {
                label: "Events",
                to: "https://www.apache.org/events/current-event.html",
              },
              {
                label: "Privacy",
                to: "https://privacy.apache.org/policies/privacy-policy-public.html",
              },
              {
                label: "Security",
                to: "https://www.apache.org/security/",
              },
              {
                label: "Sponsorship",
                to: "https://www.apache.org/foundation/sponsorship.html",
              },
              {
                label: "Thanks",
                to: "https://www.apache.org/foundation/thanks.html",
              },
              {
                label: "Code of Conduct",
                to: "https://www.apache.org/foundation/policies/conduct.html",
              },
            ],
          },
          {
            href: repoAddress,
            position: "right",
            className: "header-github-link",
            "aria-label": "GitHub repository",
          },
          {
            href: "https://discord.gg/XQy8yGR2dg",
            position: "right",
            className: "header-discord-link",
            "aria-label": "Discord",
          },
        ],
      },
      footer: {
        style: "light",
        logo: {
          alt: "Apache Software Foundation",
          src: "./img/asf_logo_wide.svg",
          href: "https://www.apache.org/",
          width: 300,
        },
        copyright: `Copyright © 2022-${new Date().getFullYear()}, The Apache Software Foundation<br/>Reqsign is a subproject of Apache OpenDAL™, governed by the Apache OpenDAL PMC.<br/>Apache OpenDAL, OpenDAL, Apache, the Apache feather and the Apache OpenDAL project logo are either registered trademarks or trademarks of the Apache Software Foundation.`,
      },
      prism: {
        theme: themes.github,
        darkTheme: themes.dracula,
        additionalLanguages: ["rust", "toml", "bash"],
      },
    }),
};

module.exports = config;
