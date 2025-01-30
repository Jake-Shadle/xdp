//! This is a minimal set of type definitions/helpers for common network types,
//! so one does not need to depend on eg. network-types which lacks comments

use super::{csum, Pod};
use std::{
    fmt,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
};

macro_rules! len {
    ($record:ty) => {
        unsafe impl Pod for $record {}

        impl $record {
            /// The length in bytes of this type
            pub const LEN: usize = size_of::<$record>();
        }
    };
}

macro_rules! net_int {
    ($name:ident, $int:ty, $fmt:literal) => {
        /// Wrapper around a network order integer
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(C)]
        pub struct $name(pub $int);

        impl $name {
            /// Gets the type in host order
            #[inline]
            pub fn host(self) -> $int {
                <$int>::from_be(self.0)
            }
        }

        impl From<$int> for $name {
            #[inline]
            fn from(v: $int) -> Self {
                Self(v.to_be())
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, $fmt, self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, $fmt, self.host())
            }
        }
    };
}

net_int!(NetworkU16, u16, "{:04x}");
net_int!(NetworkU32, u32, "{:08x}");

/// A [MAC address](https://en.wikipedia.org/wiki/MAC_address)
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// An [Ethernet II](https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II) header
#[repr(C)]
pub struct EthHdr {
    /// The destination MAC address
    pub destination: MacAddress,
    /// The source MAC address
    pub source: MacAddress,
    /// The [`EtherType`] determines the rest of the payload
    pub ether_type: EtherType,
}

len!(EthHdr);

/// The [payload](https://en.wikipedia.org/wiki/EtherType) for an Ethernet frame
#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum EtherType {
    /// The payload is an [`Ipv4Hdr`]
    Ipv4 = 0x0800_u16.to_be(),
    /// [Address Resolution Protocol](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
    Arp = 0x0806_u16.to_be(),
    /// The payload is an [`Ipv6Hdr`]
    Ipv6 = 0x86DD_u16.to_be(),
}

/// Various transport layer protocols that can be encapsulated in an IPv4 or IPv6
/// packet
///
/// <https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers>
#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[allow(clippy::doc_markdown)]
pub enum IpProto {
    /// IPv6 Hop-by-Hop Option
    HopOpt = 0,
    /// Internet Control Message
    Icmp = 1,
    /// Internet Group Management
    Igmp = 2,
    /// Gateway-to-Gateway
    Ggp = 3,
    /// IPv4 encapsulation
    Ipv4 = 4,
    /// Stream
    Stream = 5,
    /// Transmission Control
    Tcp = 6,
    /// CBT
    Cbt = 7,
    /// Exterior Gateway Protocol
    Egp = 8,
    /// Any private interior gateway (used by Cisco for their IGRP)
    Igp = 9,
    /// BBN RCC Monitoring
    BbnRccMon = 10,
    /// Network Voice Protocol
    NvpII = 11,
    /// PUP
    Pup = 12,
    /// ARGUS
    Argus = 13,
    /// EMCON
    Emcon = 14,
    /// Cross Net Debugger
    Xnet = 15,
    /// Chaos
    Chaos = 16,
    /// [User Datagram](struct@UdpHdr)
    Udp = 17,
    /// Multiplexing
    Mux = 18,
    /// DCN Measurement Subsystems
    DcnMeas = 19,
    /// Host Monitoring
    Hmp = 20,
    /// Packet Radio Measurement
    Prm = 21,
    /// XEROX NS IDP
    Idp = 22,
    /// Trunk-1
    Trunk1 = 23,
    /// Trunk-2
    Trunk2 = 24,
    /// Leaf-1
    Leaf1 = 25,
    /// Leaf-2
    Leaf2 = 26,
    /// Reliable Data Protocol
    Rdp = 27,
    /// Internet Reliable Transaction
    Irtp = 28,
    /// ISO Transport Protocol Class 4
    Tp4 = 29,
    /// Bulk Data Transfer Protocol
    Netblt = 30,
    /// MFE Network Services Protocol
    MfeNsp = 31,
    /// MERIT Internodal Protocol
    MeritInp = 32,
    /// Datagram Congestion Control Protocol
    Dccp = 33,
    /// Third Party Connect Protocol
    ThirdPartyConnect = 34,
    /// Inter-Domain Policy Routing Protocol
    Idpr = 35,
    /// XTP
    Xtp = 36,
    /// Datagram Delivery Protocol
    Ddp = 37,
    /// IDPR Control Message Transport Proto
    IdprCmtp = 38,
    /// TP++ Transport Protocol
    TpPlusPlus = 39,
    /// IL Transport Protocol
    Il = 40,
    /// IPv6 encapsulation
    Ipv6 = 41,
    /// Source Demand Routing Protocol
    Sdrp = 42,
    /// Routing Header for IPv6
    Ipv6Route = 43,
    /// Fragment Header for IPv6
    Ipv6Frag = 44,
    /// Inter-Domain Routing Protocol
    Idrp = 45,
    /// Reservation Protocol
    Rsvp = 46,
    /// General Routing Encapsulation
    Gre = 47,
    /// Dynamic Source Routing Protocol
    Dsr = 48,
    /// BNA
    Bna = 49,
    /// Encap Security Payload
    Esp = 50,
    /// Authentication Header
    Ah = 51,
    /// Integrated Net Layer Security TUBA
    Inlsp = 52,
    /// IP with Encryption
    Swipe = 53,
    /// NBMA Address Resolution Protocol
    Narp = 54,
    /// IP Mobility
    Mobile = 55,
    /// Transport Layer Security Protocol using Kryptonet key management
    Tlsp = 56,
    /// SKIP
    Skip = 57,
    /// Internet Control Message Protocol for IPv6
    Ipv6Icmp = 58,
    /// No Next Header for IPv6
    Ipv6NoNxt = 59,
    /// Destination Options for IPv6
    Ipv6Opts = 60,
    /// Any host internal protocol
    AnyHostInternal = 61,
    /// CFTP
    Cftp = 62,
    /// Any local network
    AnyLocalNetwork = 63,
    /// SATNET and Backroom EXPAK
    SatExpak = 64,
    /// Kryptolan
    Kryptolan = 65,
    /// MIT Remote Virtual Disk Protocol
    Rvd = 66,
    /// Internet Pluribus Packet Core
    Ippc = 67,
    /// Any distributed file system
    AnyDistributedFileSystem = 68,
    /// SATNET Monitoring
    SatMon = 69,
    /// VISA Protocol
    Visa = 70,
    /// Internet Packet Core Utility
    Ipcv = 71,
    /// Computer Protocol Network Executive
    Cpnx = 72,
    /// Computer Protocol Heart Beat
    Cphb = 73,
    /// Wang Span Network
    Wsn = 74,
    /// Packet Video Protocol
    Pvp = 75,
    /// Backroom SATNET Monitoring
    BrSatMon = 76,
    /// SUN ND PROTOCOL-Temporary
    SunNd = 77,
    /// WIDEBAND Monitoring
    WbMon = 78,
    /// WIDEBAND EXPAK
    WbExpak = 79,
    /// ISO Internet Protocol
    IsoIp = 80,
    /// VMTP
    Vmtp = 81,
    /// SECURE-VMTP
    SecureVmtp = 82,
    /// VINES
    Vines = 83,
    /// Transaction Transport Protocol
    Ttp = 84,
    /// NSFNET-IGP
    NsfnetIgp = 85,
    /// Dissimilar Gateway Protocol
    Dgp = 86,
    /// TCF
    Tcf = 87,
    /// EIGRP
    Eigrp = 88,
    /// OSPFIGP
    Ospfigp = 89,
    /// Sprite RPC Protocol
    SpriteRpc = 90,
    /// Locus Address Resolution Protocol
    Larp = 91,
    /// Multicast Transport Protocol
    Mtp = 92,
    /// AX.25 Frames
    Ax25 = 93,
    /// IP-within-IP Encapsulation Protocol
    Ipip = 94,
    /// Mobile Internetworking Control Pro.
    Micp = 95,
    /// Semaphore Communications Sec. Pro.
    SccSp = 96,
    /// Ethernet-within-IP Encapsulation
    Etherip = 97,
    /// Encapsulation Header
    Encap = 98,
    /// Any private encryption scheme
    AnyPrivateEncryptionScheme = 99,
    /// GMTP
    Gmtp = 100,
    /// Ipsilon Flow Management Protocol
    Ifmp = 101,
    /// PNNI over IP
    Pnni = 102,
    /// Protocol Independent Multicast
    Pim = 103,
    /// ARIS
    Aris = 104,
    /// SCPS
    Scps = 105,
    /// QNX
    Qnx = 106,
    /// Active Networks
    ActiveNetworks = 107,
    /// IP Payload Compression Protocol
    IpComp = 108,
    /// Sitara Networks Protocol
    Snp = 109,
    /// Compaq Peer Protocol
    CompaqPeer = 110,
    /// IPX in IP
    IpxInIp = 111,
    /// Virtual Router Redundancy Protocol
    Vrrp = 112,
    /// PGM Reliable Transport Protocol
    Pgm = 113,
    /// Any 0-hop protocol
    AnyZeroHopProtocol = 114,
    /// Layer Two Tunneling Protocol
    L2tp = 115,
    /// D-II Data Exchange (DDX)
    Ddx = 116,
    /// Interactive Agent Transfer Protocol
    Iatp = 117,
    /// Schedule Transfer Protocol
    Stp = 118,
    /// SpectraLink Radio Protocol
    Srp = 119,
    /// UTI
    Uti = 120,
    /// Simple Message Protocol
    Smp = 121,
    /// Simple Multicast Protocol
    Sm = 122,
    /// Performance Transparency Protocol
    Ptp = 123,
    /// ISIS over IPv4
    IsisOverIpv4 = 124,
    /// FIRE
    Fire = 125,
    /// Combat Radio Transport Protocol
    Crtp = 126,
    /// Combat Radio User Datagram
    Crudp = 127,
    /// SSCOPMCE
    Sscopmce = 128,
    /// IPLT
    Iplt = 129,
    /// Secure Packet Shield
    Sps = 130,
    /// Private IP Encapsulation within IP
    Pipe = 131,
    /// Stream Control Transmission Protocol
    Sctp = 132,
    /// Fibre Channel
    Fc = 133,
    /// RSVP-E2E-IGNORE
    RsvpE2eIgnore = 134,
    /// Mobility Header
    MobilityHeader = 135,
    /// Lightweight User Datagram Protocol
    UdpLite = 136,
    /// MPLS-in-IP
    Mpls = 137,
    /// MANET Protocols
    Manet = 138,
    /// Host Identity Protocol
    Hip = 139,
    /// Shim6 Protocol
    Shim6 = 140,
    /// Wrapped Encapsulating Security Payload
    Wesp = 141,
    /// Robust Header Compression
    Rohc = 142,
    /// Ethernet in IPv4
    EthernetInIpv4 = 143,
    /// AGGFRAG encapsulation payload for ESP
    Aggfrag = 144,
    /// Use for experimentation and testing
    Test1 = 253,
    /// Use for experimentation and testing
    Test2 = 254,
    /// Reserved
    Reserved = 255,
}

/// The [IPv4](https://en.wikipedia.org/wiki/IPv4) header
#[repr(C)]
pub struct Ipv4Hdr {
    bitfield: u16,
    /// The [total length](https://en.wikipedia.org/wiki/IPv4#Total_Length) of the packet,
    /// including the header, protocol, and the data payload
    pub total_length: NetworkU16,
    /// The [identification](https://en.wikipedia.org/wiki/IPv4#Identification)
    pub identification: NetworkU16,
    fragment: u16,
    /// Technically this is a time in units of seconds, but in reality this is
    /// used as a [hop count](https://en.wikipedia.org/wiki/Hop_(networking))
    /// and should be decremented if resending this packet
    #[doc(alias = "ttl")]
    pub time_to_live: u8,
    /// The layer 4 protocol encapsulated in this packet
    pub proto: IpProto,
    /// The [checksum](https://en.wikipedia.org/wiki/Internet_checksum) of the
    /// fields in this header, with the check field itself being 0
    pub check: u16,
    /// The source [IP](https://en.wikipedia.org/wiki/IPv4#Addressing)
    pub source: NetworkU32,
    /// The destination [IP](https://en.wikipedia.org/wiki/IPv4#Addressing)
    pub destination: NetworkU32,
}

impl Ipv4Hdr {
    /// Zeroes out the header
    #[inline]
    pub fn reset(&mut self, ttl: u8, proto: IpProto) {
        *self = Self::zeroed();
        self.bitfield = 0x0045;
        self.time_to_live = ttl;
        self.proto = proto;
    }

    /// Gets the [Internet Header Length](https://en.wikipedia.org/wiki/IPv4#IHL),
    /// the total length of the header, including options, in bytes
    ///
    /// This value is in the range `[20..=60]`
    #[doc(alias = "ihl")]
    #[inline]
    pub fn internet_header_length(&self) -> u8 {
        ((self.bitfield & 0x000f) * 4) as u8
    }

    /// Recalculates the [`Self::check`] field based on the current contents
    /// of the header
    #[inline]
    pub fn calc_checksum(&mut self) {
        self.check = 0;
        self.check = csum::fold_checksum(csum::partial(self.as_bytes(), 0));
    }
}

len!(Ipv4Hdr);

/// The [IPv6](https://en.wikipedia.org/wiki/IPv6) header
#[repr(C)]
pub struct Ipv6Hdr {
    bitfield: u32,
    /// The payload length of the packet, note that for Ipv6 this does not include
    /// the base header length of 40
    pub payload_length: NetworkU16,
    /// The next header, usually the transport layer protocol, but could be one
    /// or more [extension headers](https://en.wikipedia.org/wiki/IPv6_packet#Extension_headers)
    pub next_header: IpProto,
    /// The equivalent of [`Ipv4Hdr::time_to_live`].
    ///
    /// This value is decremented by one at each forwarding node and the packet
    /// is discarded if it becomes 0. However, the destination node should process
    /// the packet normally even if received with a hop limit of 0.
    pub hop_limit: u8,
    /// The source [IP](https://en.wikipedia.org/wiki/IPv6_address)
    pub source: [u8; 16],
    /// The destination [IP](https://en.wikipedia.org/wiki/IPv6_address)
    pub destination: [u8; 16],
}

impl Ipv6Hdr {
    /// Zeroes out the header
    #[inline]
    pub fn reset(&mut self, hop: u8, proto: IpProto) {
        *self = Self::zeroed();

        self.bitfield = 0x00000060;
        self.next_header = proto;
        self.hop_limit = hop;
    }
}

len!(Ipv6Hdr);

/// The [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) header
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UdpHdr {
    /// The source port of the sender
    pub source: NetworkU16,
    /// The destination port
    pub dest: NetworkU16,
    /// The length of this header and the data portion following it
    pub len: NetworkU16,
    /// The [checksum](https://en.wikipedia.org/wiki/Internet_checksum) of
    /// the [IPv4 pseudo header](https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv4_pseudo_header) or
    /// [IPv6 pseudo header](https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv6_pseudo_header),
    /// this header (with the `check` field set to 0), and the data payload
    pub check: u16,
}

len!(UdpHdr);

/// The IP (L3) address information for a packet
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpAddresses {
    /// IPv4 addresses
    V4 {
        /// Source IP
        source: Ipv4Addr,
        /// Destination IP
        destination: Ipv4Addr,
    },
    /// IPv6 addresses
    V6 {
        /// Source IP
        source: Ipv6Addr,
        /// Destination IP
        destination: Ipv6Addr,
    },
}

use std::net::IpAddr;

impl IpAddresses {
    /// Gets the source IP address
    #[inline]
    pub fn source(&self) -> IpAddr {
        match self {
            Self::V4 { source, .. } => (*source).into(),
            Self::V6 { source, .. } => (*source).into(),
        }
    }

    /// Gets the destination IP address
    #[inline]
    pub fn destination(&self) -> IpAddr {
        match self {
            Self::V4 { destination, .. } => (*destination).into(),
            Self::V6 { destination, .. } => (*destination).into(),
        }
    }

    /// Gets both the source and destination IP addresses
    #[inline]
    pub fn both(&self) -> (IpAddr, IpAddr) {
        match self {
            Self::V4 {
                source,
                destination,
                ..
            } => ((*source).into(), (*destination).into()),
            Self::V6 {
                source,
                destination,
                ..
            } => ((*source).into(), (*destination).into()),
        }
    }
}

/// UDP packet information that can be parsed and/or written from/to a [`super::Packet`]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UdpPacket {
    /// The IP source and destination information
    pub ips: IpAddresses,
    /// The source MAC address
    pub src_mac: MacAddress,
    /// The destination MAC address
    pub dst_mac: MacAddress,
    /// The source UDP port
    pub src_port: NetworkU16,
    /// The destination UDP port
    pub dst_port: NetworkU16,
    /// The offset to the beginning of the data segment
    pub data_offset: usize,
    /// The length of the data segment
    pub data_length: usize,
    /// The IPv4 time-to-live, or IPv6 hop limit
    pub hop: u8,
    /// The UDP checksum
    pub checksum: NetworkU16,
}

impl UdpPacket {
    /// Attempts to parse a [`Self`] from a packet.
    ///
    /// Returns `Ok(None)` if the packet doesn't seem corrupted, but doesn't
    /// actually contain a UDP packet
    ///
    /// # Errors
    ///
    /// Errors in cases where the data can be partially parsed but the size of the
    /// packet data indicates a corrupt/invalid packet
    pub fn parse_packet(packet: &super::Packet) -> Result<Option<Self>, super::PacketError> {
        let mut offset = 0;
        let ether: &EthHdr = packet.item_at_offset(offset)?;
        offset += EthHdr::LEN;

        let (udp, ips, hop): (&UdpHdr, IpAddresses, u8) = match ether.ether_type {
            EtherType::Ipv4 => {
                let ipv4: &Ipv4Hdr = packet.item_at_offset(offset)?;
                offset += Ipv4Hdr::LEN;

                if ipv4.proto == IpProto::Udp {
                    (
                        packet.item_at_offset(offset)?,
                        IpAddresses::V4 {
                            source: ipv4.source.host().into(),
                            destination: ipv4.destination.host().into(),
                        },
                        ipv4.time_to_live,
                    )
                } else {
                    return Ok(None);
                }
            }
            EtherType::Ipv6 => {
                let ipv6: &Ipv6Hdr = packet.item_at_offset(offset)?;
                offset += Ipv6Hdr::LEN;

                if ipv6.next_header == IpProto::Udp {
                    (
                        packet.item_at_offset(offset)?,
                        IpAddresses::V6 {
                            source: ipv6.source.into(),
                            destination: ipv6.destination.into(),
                        },
                        ipv6.hop_limit,
                    )
                } else {
                    return Ok(None);
                }
            }
            EtherType::Arp => {
                return Ok(None);
            }
        };

        offset += UdpHdr::LEN;

        let data_length = udp.len.host() as usize - UdpHdr::LEN;

        Ok(Some(Self {
            src_mac: ether.source,
            dst_mac: ether.destination,
            src_port: udp.source,
            dst_port: udp.dest,
            ips,
            data_offset: offset,
            data_length,
            hop,
            checksum: NetworkU16(udp.check),
        }))
    }

    /// True if and IPv4 packet
    #[inline]
    pub fn is_ipv4(&self) -> bool {
        matches!(&self.ips, IpAddresses::V4 { .. })
    }

    /// The total length of the header segments before the data segment
    #[inline]
    pub fn header_length(&self) -> usize {
        EthHdr::LEN
            + if self.is_ipv4() {
                Ipv4Hdr::LEN
            } else {
                Ipv6Hdr::LEN
            }
            + UdpHdr::LEN
    }

    /// Sets the packet's head to the IP and UDP headers, the packet must have
    /// enough space
    pub fn set_packet_headers(&self, packet: &mut super::Packet) -> Result<(), super::PacketError> {
        let mut offset = 0;
        let ether: &mut EthHdr = packet.item_at_offset_mut(offset)?;
        offset += EthHdr::LEN;

        ether.destination = self.dst_mac;
        ether.source = self.src_mac;

        match self.ips {
            IpAddresses::V4 {
                source,
                destination,
            } => {
                ether.ether_type = EtherType::Ipv4;

                let ip: &mut Ipv4Hdr = packet.item_at_offset_mut(offset)?;
                offset += Ipv4Hdr::LEN;

                ip.reset(self.hop, IpProto::Udp);
                ip.source = source.to_bits().into();
                ip.destination = destination.to_bits().into();
                ip.total_length = ((Ipv4Hdr::LEN + UdpHdr::LEN + self.data_length) as u16).into();

                // Technically we only need to the IPv4 checksum and can set the
                // UDP checksum to 0
                ip.calc_checksum();
            }
            IpAddresses::V6 {
                source,
                destination,
            } => {
                ether.ether_type = EtherType::Ipv6;

                let ip: &mut Ipv6Hdr = packet.item_at_offset_mut(offset)?;
                offset += Ipv6Hdr::LEN;

                ip.reset(self.hop, IpProto::Udp);
                ip.source = source.octets();
                ip.destination = destination.octets();
                ip.payload_length = ((UdpHdr::LEN + self.data_length) as u16).into();
            }
        }

        let udp: &mut UdpHdr = packet.item_at_offset_mut(offset)?;
        udp.source = self.src_port;
        udp.dest = self.dst_port;
        udp.len = ((self.data_length + UdpHdr::LEN) as u16).into();
        udp.check = self.checksum.0;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn sanity_check() {
        use super::*;

        assert_eq!(EthHdr::LEN, 14);
        assert_eq!(Ipv4Hdr::LEN, 20);
        assert_eq!(Ipv6Hdr::LEN, 40);
        assert_eq!(UdpHdr::LEN, 8);

        let mut ip = Ipv4Hdr::zeroed();
        ip.reset(56, IpProto::Tcp);
        assert_eq!(20, ip.internet_header_length());
    }
}
