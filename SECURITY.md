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

# Security Policy

## Reporting a Vulnerability

Apache OpenDAL Reqsign follows the
[Apache Software Foundation security process](https://www.apache.org/security/).
Please report suspected vulnerabilities privately to
`private@opendal.apache.org`. If you are unsure where to send the report, use
the ASF Security Team address, `security@apache.org`. Do not open public GitHub
issues or pull requests for security reports.

When reporting, include:

- the affected crate name and version;
- the affected signing service, such as AWS SigV4, Azure Storage, Google,
  Aliyun OSS, Huawei Cloud OBS, Oracle Cloud, Tencent COS, Volcengine TOS,
  or another supported service;
- whether the issue affects direct `reqsign` use, Apache OpenDAL integration,
  or another embedding application;
- a minimal reproduction, affected request, credential-provider configuration,
  and expected versus actual behavior;
- whether credentials, bearer tokens, private keys, signed URLs, logs, or debug
  output were exposed.

## Threat Model

The security boundary, in-scope findings, out-of-scope deployment issues, and
triage guidance for this repository are documented in
[THREAT_MODEL.md](./THREAT_MODEL.md).

Apache OpenDAL is Reqsign's primary integration for custom key signing and
cloud-provider authentication, but Reqsign can also be embedded directly by
other applications. OpenDAL-specific storage behavior, operator authorization,
path policy, and storage-service trust boundaries are covered by OpenDAL's own
security documentation.
