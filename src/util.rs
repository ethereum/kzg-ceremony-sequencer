use eyre::{bail, ensure, Result as EyreResult};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str,
};
use std::convert::Infallible;
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

#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    #[must_use]
    pub fn get_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl str::FromStr for Secret {
    type Err = Infallible;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        Ok(Self(str.to_owned()))
    }
}
