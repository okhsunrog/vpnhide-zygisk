//! Pure logic: is a given interface name a VPN tunnel?
//!
//! Kept as a leaf module with no dependencies so it's easy to unit-test on
//! the host. The set of prefixes must stay in sync with the Kotlin LSPosed
//! module's `isVpnInterfaceName`.

use core::ffi::CStr;

/// Interface name prefixes we treat as "this is a VPN tunnel". Any name
/// starting with one of these, or containing the substring `"vpn"`, is
/// hidden from the target app.
const VPN_PREFIXES: &[&[u8]] = &[
    b"tun",   // OpenVPN / WireGuard user-space / Tailscale / most tunneling
    b"ppp",   // PPTP / L2TP PPP tunnels
    b"tap",   // OpenVPN bridged mode
    b"wg",    // in-kernel WireGuard
    b"ipsec", // Android built-in IPsec VPN
    b"xfrm",  // kernel IPsec XFRM framework interfaces
    b"utun",  // Apple-style, rare on Android
    b"l2tp",  // L2TP
    b"gre",   // GRE tunnels
];

const VPN_SUBSTRING: &[u8] = b"vpn";

/// True if the bytes look like a VPN tunnel interface name.
///
/// Case-insensitive, works on raw `&[u8]` so we can call it straight from
/// a `libc::ifreq.ifr_name` buffer (which is `[c_char; IFNAMSIZ]`) without
/// having to copy into a String.
pub fn is_vpn_iface_bytes(name: &[u8]) -> bool {
    // Trim at the first NUL — ifr_name is a fixed-size buffer with a NUL
    // terminator somewhere inside it.
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let name = &name[..end];
    if name.is_empty() {
        return false;
    }

    // Ascii-lowercase compare for the prefix check
    let matches_prefix = VPN_PREFIXES.iter().any(|prefix| {
        name.len() >= prefix.len()
            && name[..prefix.len()]
                .iter()
                .zip(prefix.iter())
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
    });
    if matches_prefix {
        return true;
    }

    // Substring check: "vpn" anywhere in the name
    contains_ignore_ascii_case(name, VPN_SUBSTRING)
}

/// Convenience wrapper: takes a `CStr` and dispatches to `is_vpn_iface_bytes`.
#[allow(dead_code)]
pub fn is_vpn_iface_cstr(name: &CStr) -> bool {
    is_vpn_iface_bytes(name.to_bytes())
}

/// Case-insensitive substring search for ASCII. Avoids pulling in regex or
/// heavy helpers so the library stays tiny.
fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    for start in 0..=haystack.len() - needle.len() {
        let window = &haystack[start..start + needle.len()];
        if window
            .iter()
            .zip(needle.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tun0() {
        assert!(is_vpn_iface_bytes(b"tun0"));
        assert!(is_vpn_iface_bytes(b"tun1"));
        assert!(is_vpn_iface_bytes(b"TUN0"));
    }

    #[test]
    fn detects_wireguard() {
        assert!(is_vpn_iface_bytes(b"wg0"));
        assert!(is_vpn_iface_bytes(b"wg-client"));
    }

    #[test]
    fn detects_ppp_and_l2tp() {
        assert!(is_vpn_iface_bytes(b"ppp0"));
        assert!(is_vpn_iface_bytes(b"l2tp0"));
    }

    #[test]
    fn detects_vpn_substring() {
        assert!(is_vpn_iface_bytes(b"my-vpn-iface"));
        assert!(is_vpn_iface_bytes(b"custom_VPN_42"));
    }

    #[test]
    fn rejects_real_interfaces() {
        assert!(!is_vpn_iface_bytes(b"lo"));
        assert!(!is_vpn_iface_bytes(b"wlan0"));
        assert!(!is_vpn_iface_bytes(b"rmnet16"));
        assert!(!is_vpn_iface_bytes(b"eth0"));
        assert!(!is_vpn_iface_bytes(b"dummy0"));
    }

    #[test]
    fn handles_embedded_nul_from_ifreq() {
        // IFNAMSIZ is 16 — simulate a kernel-filled ifr_name buffer
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(b"tun0");
        assert!(is_vpn_iface_bytes(&buf));

        buf.fill(0);
        buf[..5].copy_from_slice(b"wlan0");
        assert!(!is_vpn_iface_bytes(&buf));
    }

    #[test]
    fn empty_name_is_not_vpn() {
        assert!(!is_vpn_iface_bytes(b""));
        assert!(!is_vpn_iface_bytes(&[0u8; 16]));
    }
}
