use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use tracing::{debug, error, warn};

/// Proxy validation mode
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyValidationMode {
    /// Strict allowlist mode - only explicitly allowed hosts are permitted
    Allowlist,
    /// Open mode with restrictions - allow all public hosts except blocked ones
    OpenWithRestrictions,
}

impl Default for ProxyValidationMode {
    fn default() -> Self {
        ProxyValidationMode::Allowlist
    }
}

/// Configuration for proxy validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyValidationConfig {
    /// Whether proxy validation is enabled
    pub enabled: bool,
    /// Validation mode
    pub mode: ProxyValidationMode,
    /// List of allowed hostnames/IPs (used in allowlist mode)
    pub allowed_hosts: Vec<String>,
    /// List of blocked hostnames/IPs (used in open_with_restrictions mode)
    pub blocked_hosts: Vec<String>,
    /// List of allowed ports (if empty, all ports are allowed)
    pub allowed_ports: Vec<u16>,
    /// Whether to allow localhost connections
    pub allow_localhost: bool,
    /// Whether to allow private IP ranges (RFC 1918)
    pub allow_private_ips: bool,
}

impl Default for ProxyValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: ProxyValidationMode::default(),
            allowed_hosts: vec![
                "raw.githubusercontent.com".to_string(),
                "api.github.com".to_string(),
                "httpbin.org".to_string(),
            ],
            blocked_hosts: vec![],
            allowed_ports: vec![443, 80],
            allow_localhost: false,
            allow_private_ips: false,
        }
    }
}

/// Validator for proxy connection requests
#[derive(Debug, Clone)]
pub struct ProxyValidator {
    config: ProxyValidationConfig,
}

impl ProxyValidator {
    /// Create a new proxy validator with the given configuration
    pub fn new(config: ProxyValidationConfig) -> Self {
        Self { config }
    }

    /// Validate a proxy connection request
    pub fn validate_connection(&self, host: &str, port: u16) -> Result<()> {
        if !self.config.enabled {
            debug!("Proxy validation disabled, allowing connection to {}:{}", host, port);
            return Ok(());
        }

        debug!("Validating proxy connection to {}:{} using {:?} mode", host, port, self.config.mode);

        // Check if port is allowed
        if !self.config.allowed_ports.is_empty() && !self.config.allowed_ports.contains(&port) {
            warn!("Port {} not in allowed ports list", port);
            return Err(eyre!("Port {} is not allowed", port));
        }

        match self.config.mode {
            ProxyValidationMode::Allowlist => {
                self.validate_allowlist_mode(host, port)
            }
            ProxyValidationMode::OpenWithRestrictions => {
                self.validate_open_mode(host, port)
            }
        }
    }

    /// Validate connection in allowlist mode (strict)
    fn validate_allowlist_mode(&self, host: &str, port: u16) -> Result<()> {
        // Check if host is explicitly allowed
        if self.config.allowed_hosts.contains(&host.to_string()) {
            debug!("Host {} is explicitly allowed in allowlist", host);
            return Ok(());
        }

        // Host not in allowlist - reject
        warn!("Host {} not in allowed hosts list (allowlist mode)", host);
        Err(eyre!("Host {} is not in the allowed hosts list", host))
    }

    /// Validate connection in open mode (with restrictions)
    fn validate_open_mode(&self, host: &str, port: u16) -> Result<()> {
        // Check if host is explicitly blocked
        if self.config.blocked_hosts.contains(&host.to_string()) {
            warn!("Host {} is explicitly blocked", host);
            return Err(eyre!("Host {} is blocked", host));
        }

        // Try to resolve the host to check IP restrictions
        match self.resolve_host(host, port) {
            Ok(socket_addr) => {
                let ip = socket_addr.ip();
                
                // Check localhost restriction
                if ip.is_loopback() && !self.config.allow_localhost {
                    warn!("Localhost connections not allowed for {}", host);
                    return Err(eyre!("Localhost connections are not allowed"));
                }

                // Check private IP restriction
                if self.is_private_ip(&ip) && !self.config.allow_private_ips {
                    warn!("Private IP connections not allowed for {}", host);
                    return Err(eyre!("Private IP connections are not allowed"));
                }

                debug!("Connection to {}:{} (resolved to {}) is allowed in open mode", host, port, ip);
                Ok(())
            }
            Err(e) => {
                error!("Failed to resolve host {}: {}", host, e);
                Err(eyre!("Failed to resolve host {}: {}", host, e))
            }
        }
    }

    /// Resolve a hostname to a socket address
    fn resolve_host(&self, host: &str, port: u16) -> Result<SocketAddr> {
        // Try parsing as IP address first
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }

        // Try resolving as hostname
        let addr_string = format!("{}:{}", host, port);
        let mut addrs = addr_string.to_socket_addrs()
            .map_err(|e| eyre!("DNS resolution failed: {}", e))?;

        addrs.next()
            .ok_or_else(|| eyre!("No addresses resolved for {}", host))
    }

    /// Check if an IP address is in a private range (RFC 1918, RFC 4193, etc.)
    fn is_private_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // 10.0.0.0/8
                octets[0] == 10
                // 172.16.0.0/12
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                // 192.168.0.0/16
                || (octets[0] == 192 && octets[1] == 168)
                // Link-local 169.254.0.0/16
                || (octets[0] == 169 && octets[1] == 254)
            }
            IpAddr::V6(ipv6) => {
                // Link-local fe80::/10
                let segments = ipv6.segments();
                (segments[0] & 0xffc0) == 0xfe80
                // Unique local fc00::/7
                || (segments[0] & 0xfe00) == 0xfc00
                // Site-local fec0::/10 (deprecated)
                || (segments[0] & 0xffc0) == 0xfec0
            }
        }
    }

    /// Get the current configuration
    pub fn config(&self) -> &ProxyValidationConfig {
        &self.config
    }

    /// Update the configuration
    pub fn update_config(&mut self, config: ProxyValidationConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProxyValidationConfig::default();
        assert!(config.enabled);
        assert!(!config.allowed_hosts.is_empty());
        assert!(!config.allow_localhost);
        assert!(!config.allow_private_ips);
    }

    #[test]
    fn test_validate_allowed_host() {
        let config = ProxyValidationConfig {
            enabled: true,
            allowed_hosts: vec!["example.com".to_string()],
            allowed_ports: vec![443],
            allow_localhost: false,
            allow_private_ips: false,
        };
        let validator = ProxyValidator::new(config);
        assert!(validator.validate_connection("example.com", 443).is_ok());
    }

    #[test]
    fn test_validate_disallowed_port() {
        let config = ProxyValidationConfig {
            enabled: true,
            allowed_hosts: vec!["example.com".to_string()],
            allowed_ports: vec![443],
            allow_localhost: false,
            allow_private_ips: false,
        };
        let validator = ProxyValidator::new(config);
        assert!(validator.validate_connection("example.com", 80).is_err());
    }

    #[test]
    fn test_validate_localhost_allowed() {
        let config = ProxyValidationConfig {
            enabled: true,
            allowed_hosts: vec![],
            allowed_ports: vec![],
            allow_localhost: true,
            allow_private_ips: false,
        };
        let validator = ProxyValidator::new(config);
        assert!(validator.validate_connection("127.0.0.1", 8080).is_ok());
    }

    #[test]
    fn test_validate_localhost_disallowed() {
        let config = ProxyValidationConfig {
            enabled: true,
            allowed_hosts: vec![],
            allowed_ports: vec![],
            allow_localhost: false,
            allow_private_ips: false,
        };
        let validator = ProxyValidator::new(config);
        assert!(validator.validate_connection("127.0.0.1", 8080).is_err());
    }

    #[test]
    fn test_is_private_ip() {
        let validator = ProxyValidator::new(ProxyValidationConfig::default());
        
        // IPv4 private ranges
        assert!(validator.is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(validator.is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(validator.is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(validator.is_private_ip(&"169.254.1.1".parse().unwrap()));
        
        // IPv4 public ranges
        assert!(!validator.is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!validator.is_private_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_disabled_validation() {
        let config = ProxyValidationConfig {
            enabled: false,
            allowed_hosts: vec![],
            allowed_ports: vec![],
            allow_localhost: false,
            allow_private_ips: false,
        };
        let validator = ProxyValidator::new(config);
        
        // Should allow anything when validation is disabled
        assert!(validator.validate_connection("127.0.0.1", 22).is_ok());
        assert!(validator.validate_connection("10.0.0.1", 9999).is_ok());
    }
}