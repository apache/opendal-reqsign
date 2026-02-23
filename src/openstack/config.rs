use std::collections::HashMap;
use std::env;

// Env values used in OpenStack Keystone authentication.
const OPENSTACK_AUTH_URL: &str = "OPENSTACK_AUTH_URL";
const OPENSTACK_USERNAME: &str = "OPENSTACK_USERNAME";
const OPENSTACK_PASSWORD: &str = "OPENSTACK_PASSWORD";
const OPENSTACK_DOMAIN_NAME: &str = "OPENSTACK_DOMAIN_NAME";
const OPENSTACK_PROJECT_NAME: &str = "OPENSTACK_PROJECT_NAME";
const OPENSTACK_PROJECT_DOMAIN_NAME: &str = "OPENSTACK_PROJECT_DOMAIN_NAME";

/// Config carries all the configuration for OpenStack Keystone authentication.
#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug))]
pub struct Config {
    /// The Keystone v3 identity endpoint URL.
    ///
    /// Loaded from env: [`OPENSTACK_AUTH_URL`]
    pub auth_url: Option<String>,
    /// The username for password authentication.
    ///
    /// Loaded from env: [`OPENSTACK_USERNAME`]
    pub username: Option<String>,
    /// The password for password authentication.
    ///
    /// Loaded from env: [`OPENSTACK_PASSWORD`]
    pub password: Option<String>,
    /// The user domain name. Defaults to "Default" if not set.
    ///
    /// Loaded from env: [`OPENSTACK_DOMAIN_NAME`]
    pub user_domain_name: Option<String>,
    /// The project name for scoped tokens.
    ///
    /// Loaded from env: [`OPENSTACK_PROJECT_NAME`]
    pub project_name: Option<String>,
    /// The project domain name. Falls back to `user_domain_name` if not set.
    ///
    /// Loaded from env: [`OPENSTACK_PROJECT_DOMAIN_NAME`]
    pub project_domain_name: Option<String>,
}

impl Config {
    /// Load config from environment variables.
    pub fn from_env(mut self) -> Self {
        let envs = env::vars().collect::<HashMap<_, _>>();

        if let Some(v) = envs.get(OPENSTACK_AUTH_URL) {
            self.auth_url.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(OPENSTACK_USERNAME) {
            self.username.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(OPENSTACK_PASSWORD) {
            self.password.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(OPENSTACK_DOMAIN_NAME) {
            self.user_domain_name.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(OPENSTACK_PROJECT_NAME) {
            self.project_name.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(OPENSTACK_PROJECT_DOMAIN_NAME) {
            self.project_domain_name.get_or_insert(v.clone());
        }

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env() {
        temp_env::with_vars(
            vec![
                (OPENSTACK_AUTH_URL, Some("https://keystone.example.com/v3")),
                (OPENSTACK_USERNAME, Some("testuser")),
                (OPENSTACK_PASSWORD, Some("testpass")),
                (OPENSTACK_DOMAIN_NAME, Some("Default")),
                (OPENSTACK_PROJECT_NAME, Some("myproject")),
            ],
            || {
                let config = Config::default().from_env();
                assert_eq!(
                    config.auth_url.as_deref(),
                    Some("https://keystone.example.com/v3")
                );
                assert_eq!(config.username.as_deref(), Some("testuser"));
                assert_eq!(config.password.as_deref(), Some("testpass"));
                assert_eq!(config.user_domain_name.as_deref(), Some("Default"));
                assert_eq!(config.project_name.as_deref(), Some("myproject"));
                assert!(config.project_domain_name.is_none());
            },
        );
    }

    #[test]
    fn test_config_field_takes_priority_over_env() {
        temp_env::with_vars(
            vec![(OPENSTACK_AUTH_URL, Some("https://from-env.example.com/v3"))],
            || {
                let config = Config {
                    auth_url: Some("https://from-field.example.com/v3".to_string()),
                    ..Default::default()
                }
                .from_env();
                // Field value should not be overwritten by env
                assert_eq!(
                    config.auth_url.as_deref(),
                    Some("https://from-field.example.com/v3")
                );
            },
        );
    }
}
