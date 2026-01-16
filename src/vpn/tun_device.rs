use anyhow::{Context, Result};
use std::process::Command;
use tokio::io::{ReadHalf, WriteHalf};
use tracing::{info, warn};
use tun::AsyncDevice;
use tun::Device as _;
use crate::config::NetworkConfig;

/// Wrapper around the platform-specific TUN device
pub struct TunDevice {
    device: AsyncDevice,
    config: NetworkConfig,
}

impl TunDevice {
    /// Create a new TUN device
    ///
    /// If `name` is provided, attempts to use that specific interface name.
    /// If `None`, relies on the OS to assign the next available name (e.g., utun0, utun1...).
    pub fn new(name: Option<&str>, net_config: &NetworkConfig) -> Result<Self> {
        let mut config = tun::Configuration::default();

        if let Some(n) = name {
            config.name(n);
        }

        // Parse IPv4 pool (e.g., "10.10.0.0/24")
        // We need: Server IP (e.g., 10.10.0.1), Netmask, Destination (for P2P)
        // For simplicity, we assume the first IP in the subnet is the server.
        // TODO: Use a proper CIDR library for robust parsing.
        let pool_parts: Vec<&str> = net_config.ipv4_pool.split('/').collect();
        let ip_base = pool_parts.get(0).unwrap_or(&"10.10.0.0");
        let cidr_suffix = pool_parts.get(1).unwrap_or(&"24");
        
        // Very basic IP logic for now: assume x.x.x.0 -> x.x.x.1 as server
        let server_ip = if ip_base.ends_with(".0") {
            format!("{}{}", &ip_base[..ip_base.len()-1], "1")
        } else {
            "10.10.0.1".to_string()
        };

        #[cfg(target_os = "linux")]
        {
            config.address(&server_ip);
            config.netmask("255.255.255.0"); // TODO: calculate from cidr_suffix
            config.mtu(net_config.mtu as i32);
            config.up();
        }

        #[cfg(target_os = "macos")]
        {
            config.address(&server_ip);
            config.destination("10.10.0.100"); // Point-to-point destination (Client IP)
            config.netmask("255.255.255.0");
            config.mtu(net_config.mtu as i32);
            config.up();
        }

        let device = tun::create_as_async(&config).context("Failed to create TUN device")?;

        Ok(Self { 
            device,
            config: net_config.clone()
        })
    }

    /// Split the device into read and write halves
    pub fn split(self) -> (ReadHalf<AsyncDevice>, WriteHalf<AsyncDevice>) {
        tokio::io::split(self.device)
    }

    /// Get the interface name
    pub fn name(&self) -> String {
        self.device
            .get_ref()
            .name()
            .unwrap_or_else(|_| "unknown".to_string())
    }

    /// Configure routing and NAT for the interface
    pub fn configure_routing(&self) {
        let name = self.name();

        #[cfg(target_os = "linux")]
        {
            // Enable IP forwarding
            let _ = Command::new("sysctl")
                .arg("-w")
                .arg("net.ipv4.ip_forward=1")
                .output();

            // Detect WAN interface if not configured
            let wan_iface = match &self.config.nat_interface {
                Some(iface) => iface.clone(),
                None => {
                    // Try to detect default route interface
                    // ip route show default | grep default | awk '{print $5}' | head -n 1
                    // Output format: default via 10.0.0.1 dev enp0s6 ...
                    let output = Command::new("sh")
                        .arg("-c")
                        .arg("ip route show default | grep default | awk '{print $5}' | head -n 1")
                        .output()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .unwrap_or_default();
                    
                    if output.is_empty() {
                         warn!("Could not auto-detect WAN interface for NAT. Defaulting to eth0.");
                         "eth0".to_string()
                    } else {
                        info!("Auto-detected WAN interface for NAT: {}", output);
                        output
                    }
                }
            };

            // Setup NAT (Simple Masquerade)
            // iptables -t nat -A POSTROUTING -o <wan_iface> -j MASQUERADE
            info!("Configuring Linux NAT for {} -> {}...", name, wan_iface);
            
            // First, try to clean up old rules to prevent duplicates (optional, strictly speaking)
            // But for now we just append.
            
            let _ = Command::new("iptables")
                .args(&[
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    &wan_iface,
                    "-j",
                    "MASQUERADE",
                ])
                .output();
        }

        #[cfg(target_os = "macos")]
        {
            // Enable IP forwarding
            let _ = Command::new("sysctl")
                .arg("-w")
                .arg("net.inet.ip.forwarding=1")
                .output();

            info!("Enabled IP forwarding on macOS for {}. NAT requires manual PF configuration or internet sharing.", name);
            // macOS PF (Packet Filter) automation is complex and risky to automate in dev.
            // We log a helpful message instead of potentially breaking network.
            warn!("To enable full internet access for clients on macOS:");
            warn!("  echo \"nat on en0 from 10.10.0.0/24 to any -> (en0)\" | sudo pfctl -f -");
        }
    }
}
