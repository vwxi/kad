use anyhow::{anyhow, Ok, Result};
use igd;
use local_ip_address as lip;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

/// An interface to facilitate port forwarding.
pub trait Forward {
    #[allow(unused_variables)]
    fn forward(ipv6: bool, port: u16, protocol: &str) -> Result<()> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn remove(port: u16) -> Result<()> {
        Ok(())
    }

    fn external_ip() -> Result<IpAddr> {
        Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }
}

/// No port forwarding.
#[derive(Default)]
pub struct NoFwd {}
impl Forward for NoFwd {}

/// Port forwarding using UPnP IGD capabilities.
///
/// # Quirks
///
/// * Only supports IPv4 address forwarding.  
/// * Forwarding records last forever, until removed manually.
#[derive(Default)]
pub struct IGD {}
impl Forward for IGD {
    // ipv4 only for some reason
    fn forward(_: bool, port: u16, protocol: &str) -> Result<()> {
        let gateway = igd::search_gateway(Default::default())?;
        let ip = lip::local_ip()?;
        if let IpAddr::V4(ip) = ip {
            let addr = SocketAddrV4::new(ip, port);
            gateway.add_port(igd::PortMappingProtocol::TCP, port, addr, 0, protocol)?;
            Ok(())
        } else {
            Err(anyhow!("not an IPv4 address"))
        }
    }

    fn remove(port: u16) -> Result<()> {
        let gateway = igd::search_gateway(Default::default())?;

        gateway.remove_port(igd::PortMappingProtocol::TCP, port)?;

        Ok(())
    }

    fn external_ip() -> Result<IpAddr> {
        let gateway = igd::search_gateway(Default::default())?;

        Ok(IpAddr::V4(gateway.get_external_ip()?))
    }
}
