use eyre::{bail, ensure, Result as EyreResult};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use url::{Host, Url};

pub fn parse_url(url: &Url) -> EyreResult<(SocketAddr, &str)> {
    ensure!(
        url.scheme() == "http",
        "Only http:// is supported in {}",
        url
    );
    let prefix = url.path();
    let ip: IpAddr = match url.host() {
        Some(Host::Ipv4(ip)) => ip.into(),
        Some(Host::Ipv6(ip)) => ip.into(),
        Some(_) => bail!("Cannot bind {}", url),
        None => Ipv4Addr::LOCALHOST.into(),
    };
    let port = url.port().unwrap_or(8080);
    let addr = SocketAddr::new(ip, port);
    Ok((addr, prefix))
}
