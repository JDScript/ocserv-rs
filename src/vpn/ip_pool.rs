use anyhow::{anyhow, Result};
use ipnetwork::Ipv4Network;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Manages a pool of IPv4 addresses for VPN clients
#[derive(Debug)]
pub struct IpPool {
    network: Ipv4Network,
    assigned_ips: HashSet<Ipv4Addr>,
    gateway_ip: Ipv4Addr,
}

impl IpPool {
    /// Create a new IP pool from a CIDR string (e.g., "10.10.0.0/24")
    pub fn new(cidr: &str) -> Result<Self> {
        let network: Ipv4Network = cidr.parse().map_err(|e| anyhow!("Invalid CIDR: {}", e))?;

        // Assume .1 is the gateway/server IP
        // TODO: Make gateway configurable
        let gateway_ip = network
            .nth(1)
            .ok_or_else(|| anyhow!("Network too small for gateway"))?;

        let mut assigned_ips = HashSet::new();
        // Reserve network address, broadcast address, and gateway
        assigned_ips.insert(network.network());
        assigned_ips.insert(network.broadcast());
        assigned_ips.insert(gateway_ip);

        info!("Initialized IP Pool: {}, Gateway: {}", network, gateway_ip);

        Ok(Self {
            network,
            assigned_ips,
            gateway_ip,
        })
    }

    /// Allocate the next available IP address
    pub fn allocate(&mut self) -> Result<Ipv4Addr> {
        // Simple search: iterate through all IPs in the subnet
        for ip in self.network.iter() {
            if !self.assigned_ips.contains(&ip) {
                self.assigned_ips.insert(ip);
                info!("Allocated IP: {}", ip);
                return Ok(ip);
            }
        }
        Err(anyhow!("No available IPs in pool {}", self.network))
    }

    /// Release an IP address back to the pool
    pub fn release(&mut self, ip: Ipv4Addr) {
        if ip == self.gateway_ip || ip == self.network.network() || ip == self.network.broadcast() {
            return; // Don't release reserved IPs
        }
        if self.assigned_ips.remove(&ip) {
            info!("Released IP: {}", ip);
        } else {
            warn!("Attempted to release unassigned IP: {}", ip);
        }
    }

    /// Get the gateway (server) IP
    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway_ip
    }

    /// Get the network CIDR
    pub fn network(&self) -> Ipv4Network {
        self.network
    }
}

/// Thread-safe wrapper for IpPool
#[derive(Debug, Clone)]
pub struct SharedIpPool(Arc<Mutex<IpPool>>);

impl SharedIpPool {
    pub fn new(cidr: &str) -> Result<Self> {
        Ok(Self(Arc::new(Mutex::new(IpPool::new(cidr)?))))
    }

    pub fn allocate(&self) -> Result<Ipv4Addr> {
        self.0.lock().unwrap().allocate()
    }

    pub fn release(&self, ip: Ipv4Addr) {
        self.0.lock().unwrap().release(ip)
    }

    pub fn gateway(&self) -> Ipv4Addr {
        self.0.lock().unwrap().gateway()
    }
}
