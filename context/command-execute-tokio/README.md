# reqsign-command-execute-tokio

Tokio-based command execution for reqsign.

This crate provides `TokioCommandExecute`, an implementation of
`reqsign_core::CommandExecute` backed by `tokio::process`. It is intended for
credential providers that invoke external programs, such as AWS credential
processes and cloud provider CLIs.

## Usage

```rust
use reqsign_command_execute_tokio::TokioCommandExecute;
use reqsign_core::Context;

let context = Context::new().with_command_execute(TokioCommandExecute);
```

Command execution is supported on native targets. On WebAssembly targets the
implementation returns an unsupported-operation error.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
