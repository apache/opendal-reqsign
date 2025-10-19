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
