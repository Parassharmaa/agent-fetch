use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns `true` if the IP address is private, reserved, loopback, link-local,
/// or otherwise should not be reachable from an SSRF-safe HTTP client.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    if ip.is_unspecified() {
        return true;
    }
    if ip.is_loopback() {
        return true;
    }
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 169.254.0.0/16
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    if ip.is_broadcast() {
        return true;
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (documentation)
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return true;
    }
    // 100.64.0.0/10 (CGNAT)
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }
    // 224.0.0.0/4 (multicast)
    if octets[0] >= 224 && octets[0] <= 239 {
        return true;
    }
    // 240.0.0.0/4 (reserved)
    if octets[0] >= 240 {
        return true;
    }
    false
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    if ip.is_unspecified() {
        return true;
    }

    let segments = ip.segments();

    // fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // fc00::/7 (ULA — covers fd00:ec2::254 AWS metadata too)
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // ff00::/8 (multicast)
    if segments[0] & 0xff00 == 0xff00 {
        return true;
    }

    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(v4);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_v4() {
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn private_ranges_v4() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("10.255.255.255".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("172.31.255.255".parse().unwrap()));
        assert!(is_private_ip("192.168.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn link_local_v4() {
        assert!(is_private_ip("169.254.0.1".parse().unwrap()));
        assert!(is_private_ip("169.254.169.254".parse().unwrap())); // cloud metadata
    }

    #[test]
    fn unspecified_and_broadcast() {
        assert!(is_private_ip("0.0.0.0".parse().unwrap()));
        assert!(is_private_ip("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn multicast_v4() {
        assert!(is_private_ip("224.0.0.1".parse().unwrap()));
        assert!(is_private_ip("239.255.255.255".parse().unwrap()));
    }

    #[test]
    fn reserved_v4() {
        assert!(is_private_ip("240.0.0.1".parse().unwrap()));
        assert!(is_private_ip("100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn public_v4_allowed() {
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn loopback_v6() {
        assert!(is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn unspecified_v6() {
        assert!(is_private_ip("::".parse().unwrap()));
    }

    #[test]
    fn link_local_v6() {
        assert!(is_private_ip("fe80::1".parse().unwrap()));
    }

    #[test]
    fn unique_local_v6() {
        assert!(is_private_ip("fc00::1".parse().unwrap()));
        assert!(is_private_ip("fd00::1".parse().unwrap()));
    }

    #[test]
    fn ec2_metadata_v6() {
        assert!(is_private_ip("fd00:ec2::254".parse().unwrap()));
    }

    #[test]
    fn multicast_v6() {
        assert!(is_private_ip("ff02::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_v6_private() {
        assert!(is_private_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_v6_public() {
        assert!(!is_private_ip("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn public_v6_allowed() {
        assert!(!is_private_ip("2607:f8b0:4004:800::200e".parse().unwrap()));
    }
}
