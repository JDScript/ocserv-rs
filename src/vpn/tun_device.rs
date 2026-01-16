use anyhow::{Context, Result};
use std::process::Command;
use tokio::io::{ReadHalf, WriteHalf};
use tracing::{info, warn};
use tun::AsyncDevice;
use tun::Device as _;

/// Wrapper around the platform-specific TUN device
pub struct TunDevice {
    device: AsyncDevice,
}

impl TunDevice {
    /// Create a new TUN device
    ///
    /// If `name` is provided, attempts to use that specific interface name.
    /// If `None`, relies on the OS to assign the next available name (e.g., utun0, utun1...).
    pub fn new(name: Option<&str>) -> Result<Self> {
        let mut config = tun::Configuration::default();

        if let Some(n) = name {
            config.name(n);
        }

        #[cfg(target_os = "linux")]
        {
            config.address("10.10.0.1"); // Default server IP
            config.netmask("255.255.255.0");
            config.mtu(1406); // Standard AnyConnect MTU
            config.up();
        }

        #[cfg(target_os = "macos")]
        {
            config.address("10.10.0.1");
            config.destination("10.10.0.100"); // Point-to-point destination (Client IP)
            config.netmask("255.255.255.0");
            config.mtu(1406);
            config.up();
        }

        let device = tun::create_as_async(&config).context("Failed to create TUN device")?;

        Ok(Self { device })
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

            // Setup NAT (Simple Masquerade)
            // Note: This assumes eth0 is the WAN interface.
            // In a real prod environment, this should be configurable or detected.
            info!("Configuring Linux NAT for {}...", name);
            let _ = Command::new("iptables")
                .args(&[
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    "eth0",
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
