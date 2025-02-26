use xdp::packet::net_types::MacAddress;

pub const SRC_MAC: MacAddress = MacAddress([0xb4, 0x2e, 0x99, 0x6f, 0xfa, 0x6b]);
pub const DST_MAC: MacAddress = MacAddress([0xc4, 0xea, 0x1d, 0xe3, 0x82, 0x4c]);

pub const IPV4_DATA: &[u8] = b"I'm an IPv4 packet payload";
pub const IPV6_DATA: &[u8] = b"I'm an IPv6 packet payload";
pub const LARGER: &[u8] = &[0xf3; 1001];
