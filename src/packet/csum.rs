#[inline]
pub fn fold_checksum(mut csum: u32) -> u16 {
    //csum += 0xffff;

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    !csum as u16
}

#[inline]
pub fn to_u16(mut csum: u32) -> u16 {
    csum = csum.overflowing_add(csum.rotate_left(16)).0;
    (csum >> 16) as u16
}

#[inline]
pub fn add(mut a: u32, b: u32) -> u32 {
    unsafe {
        std::arch::asm!(
            "addl {b:e}, {a:e}",
            "adcl $0, {a:e}",
            a = inout(reg) a,
            b = in(reg) b,
        );
    }

    a
}

#[inline]
pub fn sub(a: u32, b: u32) -> u32 {
    add(a, !b)
}

/// Equivalent of [`bpf_csum_diff`](https://docs.ebpf.io/linux/helper-function/bpf_csum_diff/)
#[inline]
pub fn diff(from: &[u8], to: &[u8], seed: u32) -> u16 {
    let ret = if !from.is_empty() && !to.is_empty() {
        let mut a = 0;
        let mut b = 0;
        std::thread::scope(|s| {
            s.spawn(|| a = partial(to, seed));
            s.spawn(|| b = partial(from, 0));
        });
        sub(a, b)
    } else if !to.is_empty() {
        partial(to, seed)
    } else if !from.is_empty() {
        !partial(from, !seed)
    } else {
        seed
    };

    to_u16(ret)
}

#[inline]
fn finalize(sum: u64) -> u32 {
    (sum.overflowing_add(sum.rotate_right(32)).0 >> 32) as u32
}

pub fn partial(mut buf: &[u8], sum: u32) -> u32 {
    // TODO: https://fenrus75.github.io/csum_partial/ has some more potential
    // wins, but that can be done later
    // TODO: https://stackoverflow.com/questions/78889987/how-to-perform-parallel-addition-using-avx-with-carry-overflow-fed-back-into-t
    // has a potential way to do it in SIMD which should be even better

    #[inline]
    fn update_40(mut sum: u64, bytes: &[u8]) -> u64 {
        debug_assert_eq!(bytes.len(), 40);

        unsafe {
            std::arch::asm!(
                "addq 0*8({buf}), {sum}",
                "adcq 1*8({buf}), {sum}",
                "adcq 2*8({buf}), {sum}",
                "adcq 3*8({buf}), {sum}",
                "adcq 4*8({buf}), {sum}",
                "adcq $0, {sum}",
                buf = in(reg) bytes.as_ptr(),
                sum = inout(reg) sum,
                options(att_syntax)
            );
        }

        sum
    }

    let mut sum = sum as u64;

    if buf.len() >= 80 {
        let mut sum2 = 0;
        while buf.len() >= 80 {
            sum = update_40(sum, &buf[..40]);
            sum2 = update_40(sum2, &buf[40..80]);
            buf = &buf[80..];
        }

        unsafe {
            std::arch::asm!(
                "addq {0}, {sum}",
                "adcq $0, {sum}",
                in(reg) sum2,
                sum = inout(reg) sum,
                options(att_syntax)
            );
        }
    }

    if buf.len() >= 40 {
        sum = update_40(sum, &buf[..40]);
        buf = &buf[40..];

        if buf.is_empty() {
            return finalize(sum);
        }
    }

    let len = buf.len();
    if len & 32 != 0 {
        unsafe {
            std::arch::asm!(
                "addq 0*8({buf}), {sum}",
                "adcq 1*8({buf}), {sum}",
                "adcq 2*8({buf}), {sum}",
                "adcq 3*8({buf}), {sum}",
                "adcq $0, {sum}",
                buf = in(reg) buf.as_ptr(),
                sum = inout(reg) sum,
                options(att_syntax)
            );
        }

        buf = &buf[32..];
    }

    if len & 16 != 0 {
        unsafe {
            std::arch::asm!(
                "addq 0*8({buf}), {sum}",
                "adcq 1*8({buf}), {sum}",
                "adcq $0, {sum}",
                buf = in(reg) buf.as_ptr(),
                sum = inout(reg) sum,
                options(att_syntax)
            );
        }

        buf = &buf[16..];
    }

    if len & 8 != 0 {
        unsafe {
            std::arch::asm!(
                "addq 0*8({buf}), {sum}",
                "adcq $0, {sum}",
                buf = in(reg) buf.as_ptr(),
                sum = inout(reg) sum,
                options(att_syntax)
            );
        }

        buf = &buf[8..];
    }

    if len & 7 != 0 {
        // Calculate the shift we use to keep only the remaining bytes instead
        // of the whole u64
        let shift = ((-(len as i64) << 3) & 63) as u32;

        unsafe {
            // The kernel's load_unaligned_zeropad needs to take into account
            // this load potentially crossing page boundaries, but we don't have
            // that problem because Umem chunks can't be larger than a page, period.
            let trail = {
                let mut ual: u64;
                std::arch::asm!(
                    "movq 0*8({buf}), {ual}",
                    buf = in(reg) buf.as_ptr(),
                    ual = out(reg) ual,
                    options(att_syntax)
                );

                (ual << shift) >> shift
            };

            std::arch::asm!(
                "addq {trail}, {sum}",
                "adcq $0, {sum}",
                trail = in(reg) trail,
                sum = inout(reg) sum,
                options(att_syntax)
            );
        }
    }

    finalize(sum)
}

use super::net_types as nt;

#[derive(Debug)]
pub enum UdpCalcError {
    NotIp(nt::EtherType),
    NotUdp(nt::IpProto),
    Packet(super::PacketError),
}

use std::fmt;

impl fmt::Display for UdpCalcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotIp(et) => {
                write!(f, "not an IP packet, but a {et:?}")
            }
            Self::NotUdp(proto) => {
                write!(f, "not a UDP packet, but a {proto:?}")
            }
            Self::Packet(fe) => {
                write!(f, "failed to parse packet: {fe}")
            }
        }
    }
}

impl std::error::Error for UdpCalcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Packet(fe) => Some(fe),
            _ => None,
        }
    }
}

impl From<super::PacketError> for UdpCalcError {
    #[inline]
    fn from(value: super::PacketError) -> Self {
        Self::Packet(value)
    }
}

/// Recalculates the UDP checksum for the specified packet
pub fn recalc_udp(packet: &mut super::Packet) -> Result<u16, UdpCalcError> {
    use nt::*;

    let mut offset = 0;
    let eth = packet.item_at_offset::<EthHdr>(offset)?;
    offset += EthHdr::LEN;

    let pseudo_seed = match eth.ether_type {
        EtherType::Ipv4 => {
            let ipv4 = packet.item_at_offset::<Ipv4Hdr>(offset)?;
            debug_assert_eq!(
                ipv4.internet_header_length(),
                Ipv4Hdr::LEN as u8,
                "ipv4 options are not supported"
            );
            offset += Ipv4Hdr::LEN;

            if ipv4.proto != IpProto::Udp {
                return Err(UdpCalcError::NotUdp(ipv4.proto));
            }

            let udp_hdr = packet.item_at_offset::<UdpHdr>(offset)?;

            // https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv4_pseudo_header
            unsafe {
                let mut sum = (udp_hdr.len.host() as u32).to_be() + (IpProto::Udp as u32).to_be();

                std::arch::asm!(
                    "addl {saddr:e}, {sum:e}",
                    "adcl {daddr:e}, {sum:e}",
                    "adcl $0, {sum:e}",
                    saddr = in(reg) ipv4.source.0,
                    daddr = in(reg) ipv4.destination.0,
                    sum = inout(reg) sum,
                    options(att_syntax)
                );

                sum
            }
        }
        EtherType::Ipv6 => {
            let ipv6 = packet.item_at_offset::<Ipv6Hdr>(offset)?;
            offset += Ipv6Hdr::LEN;

            if ipv6.next_header != IpProto::Udp {
                return Err(UdpCalcError::NotUdp(ipv6.next_header));
            }

            let udp_hdr = packet.item_at_offset::<UdpHdr>(offset)?;

            // https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv6_pseudo_header
            unsafe {
                let mut sum = (udp_hdr.len.host() as u64).to_be() + (IpProto::Udp as u64).to_be();

                std::arch::asm!(
                    "addq 0*8({saddr}), {sum}",
                    "adcq 1*8({saddr}), {sum}",
                    "adcq 0*8({daddr}), {sum}",
                    "adcq 1*8({daddr}), {sum}",
                    "adcq $0, {sum}",
                    saddr = in(reg) ipv6.source.as_ptr(),
                    daddr = in(reg) ipv6.destination.as_ptr(),
                    sum = inout(reg) sum,
                    options(att_syntax)
                );

                finalize(sum)
            }
        }
        other => return Err(UdpCalcError::NotIp(other)),
    };

    let check_offset = offset + std::mem::offset_of!(UdpHdr, check);

    let checksum = if packet.can_offload_checksum() {
        let udp_hdr = packet.item_at_offset_mut::<UdpHdr>(offset)?;
        let csum = fold_checksum(pseudo_seed);
        udp_hdr.check = csum;

        packet.set_tx_metadata(
            crate::packet::CsumOffload::Request(crate::bindings::xsk_tx_request {
                csum_start: offset as u16,
                csum_offset: std::mem::offset_of!(UdpHdr, check) as u16,
            }),
            false,
        )?;

        csum
    } else {
        let udp_hdr = packet.item_at_offset_mut::<UdpHdr>(offset)?;
        udp_hdr.check = 0;

        let data_payload = packet.slice_at_offset(offset, packet.len() - offset)?;
        fold_checksum(partial(data_payload, pseudo_seed))
    };

    packet
        .slice_at_offset_mut(check_offset, 2)?
        .copy_from_slice(&checksum.to_ne_bytes());

    Ok(checksum)
}

impl super::net_types::UdpPacket {
    /// Given an already calculated checksum for the data payload, or 0 if using
    /// tx checksum offload, checksums the pseudo and udp header
    #[inline]
    pub fn calc_checksum(&mut self, length: usize, data_checksum: u32) {
        use crate::packet::net_types as nt;
        self.data_length = length;

        let mut sum = data_checksum as u64;
        let data_len = self.data_length + nt::UdpHdr::LEN;

        match self.ips {
            nt::IpAddresses::V4 {
                source,
                destination,
            } => {
                // https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv4_pseudo_header
                unsafe {
                    std::arch::asm!(
                        "addq {pseudo_udp}, {sum}",
                        "adcq {saddr}, {sum}",
                        "adcq {daddr}, {sum}",
                        "adcq 0*8({udp}), {sum}",
                        "adcq $0, {sum}",
                        pseudo_udp = in(reg) ((data_len + nt::IpProto::Udp as usize) as u64).to_be(),
                        saddr = in(reg) (source.to_bits() as u64).to_be(),
                        daddr = in(reg) (destination.to_bits() as u64).to_be(),
                        udp = in(reg) &nt::UdpHdr {
                            source: self.source.port,
                            dest: self.destination.port,
                            len: (data_len as u16).into(),
                            check: 0,
                        },
                        sum = inout(reg) sum,
                        options(att_syntax)
                    );
                }
            }
            nt::IpAddresses::V6 {
                source,
                destination,
            } => {
                // https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv6_pseudo_header
                unsafe {
                    let source = source.octets();
                    let destination = destination.octets();

                    std::arch::asm!(
                        "addq {pseudo_udp}, {sum}",
                        "adcq 0*8({saddr}), {sum}",
                        "adcq 1*8({saddr}), {sum}",
                        "adcq 0*8({daddr}), {sum}",
                        "adcq 1*8({daddr}), {sum}",
                        "adcq 0*8({udp}), {sum}",
                        "adcq $0, {sum}",
                        pseudo_udp = in(reg) ((data_len + nt::IpProto::Udp as usize) as u64).to_be(),
                        saddr = in(reg) source.as_ptr(),
                        daddr = in(reg) destination.as_ptr(),
                        udp = in(reg) &nt::UdpHdr {
                            source: self.source.port,
                            dest: self.destination.port,
                            len: (data_len as u16).into(),
                            check: 0,
                        },
                        sum = inout(reg) sum,
                        options(att_syntax)
                    );
                }
            }
        }

        self.checksum.0 = fold_checksum(finalize(sum));
    }
}
