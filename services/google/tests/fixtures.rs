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

use std::fs;
use std::path::Path;

fn assert_secret_fields_are_redacted(value: &serde_json::Value, path: &Path) {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, value) in fields {
                if matches!(
                    key.as_str(),
                    "access_token"
                        | "accessToken"
                        | "id_token"
                        | "refresh_token"
                        | "client_secret"
                        | "private_key"
                        | "access_boundary_session_key"
                ) {
                    let redacted = value.as_str().is_some_and(|value| {
                        value == "REDACTED" || value.starts_with("DERIVED_TEST_")
                    });
                    assert!(redacted, "secret field {key} is not redacted in {path:?}");
                }
                assert_secret_fields_are_redacted(value, path);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                assert_secret_fields_are_redacted(value, path);
            }
        }
        _ => {}
    }
}

#[test]
fn google_response_fixtures_are_valid_json_and_redacted() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut fixture_count = 0;

    for entry in fs::read_dir(&fixture_dir).expect("Google fixture directory must exist") {
        let path = entry.expect("fixture entry must be readable").path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        fixture_count += 1;
        let content = fs::read(&path).expect("Google fixture must be readable");
        let value: serde_json::Value =
            serde_json::from_slice(&content).expect("Google fixture must contain valid JSON");
        assert_secret_fields_are_redacted(&value, &path);

        let text = String::from_utf8(content).expect("Google fixture must be UTF-8");
        for forbidden in [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "ya29.",
            "@gmail.com",
        ] {
            assert!(
                !text.contains(forbidden),
                "fixture contains forbidden credential material in {path:?}"
            );
        }
    }

    assert!(fixture_count > 0, "Google response fixtures must exist");
}
