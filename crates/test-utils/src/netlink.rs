use std::os::fd::AsRawFd;

pub fn run(cmd: &'static str, args: &[&'static str]) {
    assert!(
        std::process::Command::new(cmd)
            .args(args)
            .status()
            .expect("failed to run command")
            .success(),
        "failed to run {cmd} {args:?}"
    );
}

pub fn runf(cmd: &'static str, args: &[&'static str]) {
    std::process::Command::new(cmd)
        .args(args)
        .status()
        .expect("failed to run command");
}

pub struct Veth {
    pub name: &'static std::ffi::CStr,
    pub namespace: Namespace,
    pub ipv4: std::net::Ipv4Addr,
    pub ipv6: std::net::Ipv6Addr,
}

impl Drop for Veth {
    fn drop(&mut self) {}
}

pub struct VethPair {
    pub outside: Veth,
    pub inside: Veth,
}

#[macro_export]
macro_rules! veth_pair {
    ($name:expr, $id:expr) => {{
        let outside = concat!($name, "-outside");
        let inside = concat!($name, "-inside");

        $crate::netlink::runf("ip", &["netns", "delete", outside]);
        $crate::netlink::run("ip", &["netns", "add", outside]);
        let ons = $crate::netlink::Namespace::new(outside);

        $crate::netlink::runf("ip", &["netns", "delete", inside]);
        $crate::netlink::run("ip", &["netns", "add", inside]);
        let ins = $crate::netlink::Namespace::new(inside);

        let voutn = concat!($name, "-vout\0");
        let vinn = concat!($name, "-vin\0");

        let vout = &voutn[..voutn.len() - 1];
        let vin = &vinn[..vinn.len() - 1];

        $crate::netlink::run(
            "ip",
            &["link", "add", vout, "type", "veth", "peer", "name", vin],
        );

        $crate::netlink::run("ip", &["link", "set", vout, "netns", outside]);
        $crate::netlink::run("ip", &["link", "set", vin, "netns", inside]);

        let ipo4 = concat!("10.0.0.", $id, "/24");
        let ipo6 = concat!("::", $id, "/64");

        $crate::netlink::run("ip", &["-n", outside, "addr", "add", ipo4, "dev", vout]);
        //$crate::netlink::run("ip", &["-n", outside, "addr", "add", ipo6, "dev", vout]);

        let ipi4 = concat!("10.0.", $id, ".1/24");
        let ipi6 = concat!("::", $id, ":", $id, "/64");

        $crate::netlink::run("ip", &["-n", inside, "addr", "add", ipi4, "dev", vin]);
        //$crate::netlink::run("ip", &["-n", outside, "addr", "add", ipi6, "dev", vin]);

        // Ensure we only have 1 rx and tx queue
        $crate::netlink::run(
            "ip",
            &[
                "netns", "exec", inside, "ethtool", "-L", vin, "rx", "1", "tx", "1",
            ],
        );

        $crate::netlink::run("ip", &["-n", outside, "link", "set", vout, "up"]);
        $crate::netlink::run("ip", &["-n", inside, "link", "set", vin, "up"]);

        $crate::netlink::VethPair {
            outside: $crate::netlink::Veth {
                name: std::ffi::CStr::from_bytes_with_nul(voutn.as_bytes()).unwrap(),
                namespace: ons,
                ipv4: ipo4.strip_suffix("/24").unwrap().parse().unwrap(),
                ipv6: ipo6.strip_suffix("/64").unwrap().parse().unwrap(),
            },
            inside: $crate::netlink::Veth {
                name: std::ffi::CStr::from_bytes_with_nul(vinn.as_bytes()).unwrap(),
                namespace: ins,
                ipv4: ipi4.strip_suffix("/24").unwrap().parse().unwrap(),
                ipv6: ipi6.strip_suffix("/64").unwrap().parse().unwrap(),
            },
        }
    }};
}

pub struct Namespace {
    original: std::fs::File,
    ns: &'static str,
}

impl Namespace {
    pub fn new(ns: &'static str) -> Self {
        Self {
            original: std::fs::File::open("/proc/self/ns/net")
                .expect("failed to open current namespace"),
            ns,
        }
    }

    pub fn enter(&self) -> NamespaceCtx<'_> {
        let path = format!("/var/run/netns/{}", self.ns);
        {
            let nsf = std::fs::File::open(&path).expect("failed to open");
            if unsafe { libc::setns(nsf.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                panic!(
                    "failed to set network namespace {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        NamespaceCtx { ns: self }
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        run("ip", &["netns", "del", self.ns]);
    }
}

pub struct NamespaceCtx<'ns> {
    ns: &'ns Namespace,
}

impl Drop for NamespaceCtx<'_> {
    fn drop(&mut self) {
        if unsafe { libc::setns(self.ns.original.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            eprintln!(
                "failed to restore original namespace {}",
                std::io::Error::last_os_error()
            );
        }
    }
}
