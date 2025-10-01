// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use percent_encoding::AsciiSet;
use percent_encoding::NON_ALPHANUMERIC;

pub const TENCENTCLOUD_REGION: &str = "TENCENTCLOUD_REGION";
pub const TKE_REGION: &str = "TKE_REGION";
pub const TENCENTCLOUD_SECRET_ID: &str = "TENCENTCLOUD_SECRET_ID";
pub const TKE_SECRET_ID: &str = "TKE_SECRET_ID";
pub const TENCENTCLOUD_SECRET_KEY: &str = "TENCENTCLOUD_SECRET_KEY";
pub const TKE_SECRET_KEY: &str = "TKE_SECRET_KEY";
pub const TENCENTCLOUD_TOKEN: &str = "TENCENTCLOUD_TOKEN";
pub const TENCENTCLOUD_SECURITY_TOKEN: &str = "TENCENTCLOUD_SECURITY_TOKEN";
pub const TENCENTCLOUD_ROLE_ARN: &str = "TENCENTCLOUD_ROLE_ARN";
pub const TKE_ROLE_ARN: &str = "TKE_ROLE_ARN";
pub const TENCENTCLOUD_ROLE_SESSSION_NAME: &str = "TENCENTCLOUD_ROLE_SESSSION_NAME";
pub const TKE_ROLE_SESSSION_NAME: &str = "TKE_ROLE_SESSSION_NAME";
pub const TENCENTCLOUD_PROVIDER_ID: &str = "TENCENTCLOUD_PROVIDER_ID";
pub const TKE_PROVIDER_ID: &str = "TKE_PROVIDER_ID";
pub const TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE: &str = "TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE";
pub const TKE_IDENTITY_TOKEN_FILE: &str = "TKE_IDENTITY_TOKEN_FILE";

/// AsciiSet for [Tencent UriEncode](https://cloud.tencent.com/document/product/436/7778)
pub static TENCENT_URI_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');
