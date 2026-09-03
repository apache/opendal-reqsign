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

use reqsign_core::{Error, Result};

#[derive(Debug, serde::Deserialize)]
pub(super) struct EntraTokenResponse {
    pub(super) access_token: String,
    pub(super) expires_in: u64,
}

pub(super) fn parse_token_response(
    body: &[u8],
    response_name: &'static str,
) -> Result<EntraTokenResponse> {
    serde_json::from_slice(body).map_err(|err| {
        Error::unexpected(format!("failed to parse {response_name}")).with_source(err)
    })
}

pub(super) fn token_request_error(request_name: &'static str, status: http::StatusCode) -> Error {
    Error::credential_invalid(format!("{request_name} failed"))
        .with_context(format!("http_status: {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redacted_real_entra_response() {
        let response = include_bytes!("../../tests/fixtures/entra_token_response.json");
        let token = parse_token_response(response, "Microsoft Entra token response")
            .expect("real response fixture must parse");

        assert_eq!(token.access_token, "REDACTED");
        assert_eq!(token.expires_in, 3599);
    }
}
