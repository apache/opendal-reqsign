# reqsign-aws-v4a

`reqsign-aws-v4a` provides AWS Signature Version 4A request signing for
[`reqsign`](https://crates.io/crates/reqsign).

SigV4a uses ECDSA P-256 signatures and a signing region set, allowing one
signed request to be accepted in multiple AWS regions. See the
[AWS SigV4a signing documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).

```rust
use reqsign_aws_v4a::{RequestSigner, SigningRegionSet};

let region_set = SigningRegionSet::new("us-east-1,us-west-2")?;
let signer = RequestSigner::new("s3", region_set);
# Ok::<(), reqsign_core::Error>(())
```

Credential providers and shared AWS types are re-exported from
`reqsign-aws-core`.
