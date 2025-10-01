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

use reqsign_aliyun_oss::{DefaultCredentialProvider, RequestSigner, StaticCredentialProvider};
use reqsign_core::Result;
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::Client;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    // Create HTTP client
    let client = Client::new();

    // Create context
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::new(client.clone()))
        .with_env(OsEnv);

    // Check if we have real credentials
    let has_real_creds = ctx.env_var("ALIBABA_CLOUD_ACCESS_KEY_ID").is_some()
        && ctx.env_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET").is_some();

    let demo_mode = !has_real_creds;

    // Create request builder
    let bucket = "my-bucket"; // Replace with your bucket name
    let builder = RequestSigner::new(bucket);

    // Create the signer
    let signer = if demo_mode {
        println!("No Aliyun credentials found, using demo mode");
        println!("To use real credentials, set ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET");
        println!();

        // Use demo credentials
        let loader =
            StaticCredentialProvider::new("LTAI4GDemoAccessKeyId", "DemoAccessKeySecretForExample");
        Signer::new(ctx.clone(), loader, builder)
    } else {
        // This will try multiple sources:
        // 1. Environment variables (ALIBABA_CLOUD_ACCESS_KEY_ID, ALIBABA_CLOUD_ACCESS_KEY_SECRET)
        // 2. Assume Role with OIDC (if configured)
        let loader = DefaultCredentialProvider::new();
        Signer::new(ctx.clone(), loader, builder)
    };

    // Example 1: List objects in a bucket
    println!("Example 1: List objects in bucket");
    let url = format!("https://{bucket}.oss-cn-beijing.aliyuncs.com/");

    let req = http::Request::get(&url)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("List objects request signed successfully!");
            println!(
                "Authorization header: {:?}",
                parts.headers.get("authorization")
            );
            println!("Date header: {:?}", parts.headers.get("date"));

            if !demo_mode {
                // Execute the request only if we have real credentials
                let req = http::Request::from_parts(parts, body).try_into().map_err(
                    |e: reqwest::Error| {
                        reqsign_core::Error::unexpected("failed to convert request")
                            .with_source(anyhow::Error::new(e))
                    },
                )?;
                match client.execute(req).await {
                    Ok(resp) => {
                        println!("Response status: {}", resp.status());
                        if resp.status().is_success() {
                            let text = resp.text().await.map_err(|e| {
                                reqsign_core::Error::unexpected("failed to read response text")
                                    .with_source(anyhow::Error::new(e))
                            })?;
                            println!("Objects XML response preview:");
                            println!("{}", &text[..500.min(text.len())]);
                        }
                    }
                    Err(e) => eprintln!(
                        "Request failed: {}",
                        reqsign_core::Error::unexpected("HTTP request failed")
                            .with_source(anyhow::Error::new(e))
                    ),
                }
            } else {
                println!("Demo mode: Skipping actual API call");
                // Consume body to avoid unused variable warning
                let _ = body;
            }
        }
        Err(e) => eprintln!("Failed to sign request: {e}"),
    }

    // Example 2: Get object metadata
    println!("\nExample 2: Get object metadata");
    let object_key = "test-file.txt";
    let url = format!("https://{bucket}.oss-cn-beijing.aliyuncs.com/{object_key}");

    let req = http::Request::head(&url)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Get object metadata request signed successfully!");
            println!(
                "Authorization header: {:?}",
                parts.headers.get("authorization")
            );
            println!("Date header: {:?}", parts.headers.get("date"));
            if demo_mode {
                println!("Demo mode: Not making actual API call");
            }
        }
        Err(e) => eprintln!("Failed to sign request: {e}"),
    }

    // Example 3: Upload an object
    println!("\nExample 3: Upload an object");
    let upload_content = b"Hello from reqsign to Aliyun OSS!";
    let upload_key = "hello-oss.txt";
    let url = format!("https://{bucket}.oss-cn-beijing.aliyuncs.com/{upload_key}");

    let req = http::Request::put(&url)
        .header("Content-Type", "text/plain")
        .header("Content-Length", upload_content.len().to_string())
        .body(reqwest::Body::from(upload_content.to_vec()))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Upload object request signed successfully!");
            println!("The request is ready to upload '{upload_key}' to OSS");
            if demo_mode {
                println!("Demo mode: Not actually uploading the file");
            }
        }
        Err(e) => eprintln!("Failed to sign request: {e}"),
    }

    // Example 4: Delete an object
    println!("\nExample 4: Delete an object");
    let delete_key = "old-file.txt";
    let url = format!("https://{bucket}.oss-cn-beijing.aliyuncs.com/{delete_key}");

    let req = http::Request::delete(&url)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Delete object request signed successfully!");
            if demo_mode {
                println!("Demo mode: Not actually deleting the file");
            }
        }
        Err(e) => eprintln!("Failed to sign request: {e}"),
    }

    // Example 5: List objects with prefix
    println!("\nExample 5: List objects with prefix");
    let url = format!("https://{bucket}.oss-cn-beijing.aliyuncs.com/?prefix=photos/2024/");

    let req = http::Request::get(&url)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("List objects with prefix request signed successfully!");
            if demo_mode {
                println!("Demo mode: Not making actual API call");
            }
        }
        Err(e) => eprintln!("Failed to sign request: {e}"),
    }

    // Example 6: Using internal endpoint (VPC)
    println!("\nExample 6: Using internal endpoint");
    let internal_url =
        format!("https://{bucket}.oss-cn-beijing-internal.aliyuncs.com/{object_key}");

    let req = http::Request::get(&internal_url)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Internal endpoint request signed successfully!");
            println!("Use this when running within Aliyun VPC for better performance");
            if demo_mode {
                println!("Demo mode: Not making actual API call");
            }
        }
        Err(e) => eprintln!("Failed to sign request: {e}"),
    }

    Ok(())
}
