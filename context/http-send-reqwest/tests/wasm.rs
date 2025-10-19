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

#![cfg(target_arch = "wasm32")]

use bytes::Bytes;
use http::Request;
use reqsign_core::HttpSend;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
async fn http_send_returns_error_for_unreachable_host() {
    let client = reqwest::Client::new();
    let http_send = ReqwestHttpSend::new(client);

    let req = Request::builder()
        .method("GET")
        .uri("https://nonexistent.invalid")
        .body(Bytes::new())
        .expect("request builds");

    let result = http_send.http_send(req).await;
    assert!(
        result.is_err(),
        "expected unreachable host to produce error"
    );
}
