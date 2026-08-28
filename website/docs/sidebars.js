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

// The sidebar mirrors the user journey, not a content taxonomy:
// understand → get started → your provider → do tasks → understand deeply →
// look up behavior. Prefer fewer, complete pages over many fragments.

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
module.exports = {
  docs: [
    "what-is-reqsign",
    "comparison",
    "getting-started",
    // Provider pages render their capability facts from data/providers.json
    // (one machine-checked source); the MDX around the data holds any
    // provider-specific prose. The validator requires one page per provider.
    {
      type: "category",
      label: "Providers",
      collapsed: true,
      link: { type: "doc", id: "providers/index" },
      items: [
        "providers/aws-sigv4",
        "providers/aws-sigv4a",
        "providers/azure-storage",
        "providers/google",
        "providers/aliyun-oss",
        "providers/huaweicloud-obs",
        "providers/oracle",
        "providers/tencent-cos",
        "providers/volcengine-tos",
      ],
    },
    {
      type: "category",
      label: "Guides",
      collapsed: false,
      items: [
        "guides/credentials",
        "guides/presigning",
        "guides/granting",
        "guides/custom-runtimes",
        "guides/testing",
      ],
    },
    "architecture",
    {
      type: "category",
      label: "Reference",
      collapsed: true,
      items: [
        "reference/signing-contracts",
        "reference/versioning-and-targets",
        "reference/api",
      ],
    },
  ],
};
