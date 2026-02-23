//! OpenStack Keystone authentication support.
//!
//! Use [`OpenstackSigner`] to sign requests with a Keystone token.

mod config;
pub use config::Config as OpenstackConfig;

mod credential;
pub use credential::CatalogEntry as OpenstackCatalogEntry;
pub use credential::Credential as OpenstackCredential;
pub use credential::Endpoint as OpenstackEndpoint;
pub use credential::Loader as OpenstackLoader;

mod signer;
pub use signer::Signer as OpenstackSigner;
