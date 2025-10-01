# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

reqsign is a Rust library for signing HTTP API requests for cloud services (AWS, Azure, Google Cloud, Aliyun, Huawei Cloud, Oracle Cloud, Tencent Cloud). It follows a "build, sign, send" philosophy with modular architecture.

## Common Development Commands

### Build and Check
```bash
cargo check                                    # Analyze code without building
cargo build --workspace                        # Build all crates
cargo build --workspace --release              # Build optimized release version
```

### Testing
```bash
cargo test --no-fail-fast                      # Run all tests
cargo test --workspace --no-fail-fast          # Test entire workspace
cargo test tests::it::services::fs             # Test specific function
cargo test -p reqsign-aws-v4                   # Test specific service crate
RUST_LOG=debug cargo test                      # Test with debug logging
```

### Linting and Formatting
```bash
cargo fmt --all                                # Format all code
cargo fmt --all -- --check                     # Check formatting without changes
cargo clippy --workspace --all-targets --all-features -- -D warnings  # Lint with all features
```

### WASM Build
```bash
cargo build --workspace --target wasm32-unknown-unknown --exclude reqsign-file-read-tokio --exclude reqsign-http-send-reqwest
```

## Architecture

### Workspace Structure
- `core/` - Core signing functionality and abstractions
- `context/` - Pluggable I/O implementations:
  - `file-read-tokio/` - Async file reading with Tokio
  - `http-send-reqwest/` - HTTP client with reqwest
- `services/` - Provider-specific implementations:
  - `aws-v4/` - AWS Signature Version 4
  - `azure-storage/` - Azure Storage services
  - `google/` - Google Cloud services
  - `aliyun-oss/`, `huaweicloud-obs/`, `oracle/`, `tencent-cos/` - Other providers
- `reqsign/` - Main crate that re-exports all functionality with feature flags

### Key Design Patterns
1. **Context System**: Abstract I/O operations (file reading, HTTP sending) behind traits in `core`, with implementations in `context/`
2. **Service Modularity**: Each cloud provider is a separate crate, allowing users to include only needed providers
3. **Feature Flags**: Main `reqsign` crate uses features to control which services are included
4. **Credential Loading**: Services load credentials from environment variables, with provider-specific prefixes

### Testing Strategy
- Copy `.env.example` to `.env` and configure service credentials for integration tests
- Service tests can be disabled via environment variables (e.g., `REQSIGN_AWS_V4_TEST=false`)
- Tests require real service credentials for full integration testing
- Use `RUST_LOG=debug` for detailed test output

## Development Tips

### Adding New Services
1. Create new crate in `services/` directory
2. Implement service-specific signing logic
3. Add feature flag in main `reqsign/Cargo.toml`
4. Re-export in `reqsign/src/lib.rs` behind feature gate

### Working with Specific Services
```bash
cd services/aws-v4 && cargo test              # Test single service
cargo test -p reqsign-azure-storage           # Test from workspace root
```

### Debugging
- Set `RUST_LOG=debug` for verbose output
- Set `RUST_BACKTRACE=full` for detailed error traces
- Check `.env.example` for required environment variables per service