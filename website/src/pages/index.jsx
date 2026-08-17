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

import React from "react";
import Layout from "@theme/Layout";
import {
  Hero,
  Adoption,
  ValueProps,
  HowItWorks,
  Capabilities,
  Providers,
  FinalCta,
} from "../components/landing/sections";

export default function Home() {
  return (
    <Layout
      title="Build. Sign. Send."
      description="Apache OpenDAL™ Reqsign signs HTTP requests, loads cloud credentials, and grants scoped access for AWS, Azure, Google, Aliyun, Huawei Cloud, Oracle, Tencent, and Volcengine — without pulling in full vendor SDKs."
    >
      <main>
        <Hero />
        <Adoption />
        <ValueProps />
        <HowItWorks />
        <Capabilities />
        <Providers />
        <FinalCta />
      </main>
    </Layout>
  );
}
