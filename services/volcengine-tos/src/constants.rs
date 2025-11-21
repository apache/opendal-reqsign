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

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

pub const ENV_ACCESS_KEY_ID: &str = "VOLCENGINE_ACCESS_KEY_ID";
pub const ENV_SECRET_ACCESS_KEY: &str = "VOLCENGINE_SECRET_ACCESS_KEY";
pub const ENV_SESSION_TOKEN: &str = "VOLCENGINE_SESSION_TOKEN";

pub static VOLCENGINE_URI_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

pub static VOLCENGINE_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
