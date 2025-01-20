use std::os::fd::AsRawFd;

use xdp::nic::NicIndex;

pub struct VirtDev {
    pub index: u32,
    pub name: String,
    pub ipv4: std::net::Ipv4Addr,
    pub ipv6: std::net::Ipv6Addr,
    pub ethernet: [u8; 6],
}

impl std::fmt::Display for VirtDev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:>2}: {}: ", self.index, self.name)?;
        writeln!(
            f,
            "\tlink/ether {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.ethernet[0],
            self.ethernet[1],
            self.ethernet[2],
            self.ethernet[3],
            self.ethernet[4],
            self.ethernet[5]
        )?;
        writeln!(f, "\tinet {}/24", self.ipv4)?;
        writeln!(f, "\tinet6 {}/64", self.ipv6)?;
        Ok(())
    }
}

fn exec(cmd: &str, args: &[&str]) {
    assert!(
        std::process::Command::new(cmd)
            .args(args)
            .status()
            .expect("failed to exec command")
            .success(),
        "command `{cmd} {args:?}` failed"
    );
}

fn ip_exec(args: &[&str]) {
    exec("ip", args);
}

pub struct VethPair {
    pub first: VirtDev,
    pub second: VirtDev,
    handle: rtnetlink::Handle,
}

impl VethPair {
    pub async fn up(&self) {
        self.handle
            .link()
            .set(self.first.index)
            .up()
            .execute()
            .await
            .expect("failed to bring up");
        self.handle
            .link()
            .set(self.second.index)
            .up()
            .execute()
            .await
            .expect("failed to bring up");
    }

    //pub async fn assign_to_ns(&self, dev: &VirtDev, name: &str) {

    // let path = std::path::PathBuf::from(format!("/run/netns/{name}"));

    // let res = if path.exists() {
    //     std::fs::File::open(&path)
    // } else {
    //     let p = std::ffi::CString::new(path.as_os_str().to_str().unwrap()).unwrap();
    //     unsafe {
    //         let fd = libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL);
    //         if fd < 0 {
    //             Err(std::io::Error::last_os_error())
    //         } else {
    //             use std::os::fd::FromRawFd;
    //             Ok(std::os::fd::OwnedFd::from_raw_fd(fd).into())
    //         }
    //     }
    // };

    // let file = res.expect("failed to open namespace");
    // let index = dev.index;

    // let mut msg = self.handle.link().set(index);
    // msg.message_mut()
    //     .attributes
    //     .push(netlink_packet_route::link::LinkAttribute::NetNsFd(dbg!(
    //         file.as_raw_fd()
    //     )));

    // msg.execute().await.expect("failed to set netns");
    // file
    //}
}

impl Drop for VethPair {
    fn drop(&mut self) {
        let handle = &self.handle;
        // We only need to delete the first member of the pair, the second will be deleted automatically with it
        // since they're actually considered one unit
        let index = self.first.index;

        // async.... :(
        let res = tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current()
                .block_on(async move { handle.link().del(index).execute().await })
        });

        if let Err(e) = res {
            eprintln!(
                "failed to delete link: {e:?} `sudo ip link del {}`",
                self.first.name
            );
        }
    }
}

#[allow(dead_code)]
pub struct VirtualDevices {
    handle: rtnetlink::Handle,
    thandle: tokio::task::JoinHandle<()>,
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

impl VirtualDevices {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        let thandle = tokio::spawn(connection);

        Self { handle, thandle }
    }

    pub async fn add_pair(&self, first: String, second: String, queue_count: u32) -> VethPair {
        self.handle
            .link()
            .add()
            .veth(first.clone(), second.clone())
            .execute()
            .await
            .expect("failed to add devices");

        let first = self.setup_device(first, queue_count).await;
        let second = self.setup_device(second, queue_count).await;

        VethPair {
            first,
            second,
            handle: self.handle.clone(),
        }
    }

    // pub async fn open_namespace(&self, ns: &str) -> Namespace {
    //     rtnetlink::NetworkNamespace::add(ns.into())
    //         .await
    //         .expect("failed to create namespace");

    //     Namespace {
    //         original: std::fs::File::open("/proc/self/ns/net")
    //             .expect("failed to open current ns namespace"),
    //         ns: ns.into(),
    //     }
    // }

    pub async fn setup_device(&self, name: String, queue_count: u32) -> VirtDev {
        use futures::stream::TryStreamExt;
        let msg = self
            .handle
            .link()
            .get()
            .match_name(name.clone())
            .execute()
            .try_next()
            .await
            .expect("failed to request link index")
            .expect("failed to find link index");

        let index = msg.header.index;

        assert!(index <= u8::MAX as _);
        let i = (index & 0xff) as u8;
        let mut ethernet = [i; 6];
        // Make the MAC local
        ethernet[0] = 2;
        self.handle
            .link()
            .set(index)
            .address(ethernet.to_vec())
            .execute()
            .await
            .expect("failed to set MAC address");

        let ipv4 = std::net::Ipv4Addr::new(169, 254, i, 0);

        self.handle
            .address()
            .add(index, std::net::IpAddr::V4(ipv4), 24)
            .execute()
            .await
            .expect("failed to set IPv4 address");

        let i = (index & 0xffff) as u16;
        let ipv6 = std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, i, i, i, i);

        self.handle
            .address()
            .add(index, std::net::IpAddr::V6(ipv6), 64)
            .execute()
            .await
            .expect("failed to set IPv6 address");

        {
            let mut msg = self.handle.link().set(index);
            msg.message_mut().attributes.push(
                netlink_packet_route::link::LinkAttribute::NumTxQueues(queue_count),
            );
            msg.message_mut().attributes.push(
                netlink_packet_route::link::LinkAttribute::NumRxQueues(queue_count),
            );

            msg.execute().await.expect("failed to set number of queues");
        }

        VirtDev {
            name,
            index,
            ipv4,
            ipv6,
            ethernet,
        }
    }
}

impl Drop for VirtualDevices {
    fn drop(&mut self) {}
}

pub struct TestBed {
    namespace: &'static str,
    oip4: std::net::Ipv4Addr,
    iip4: std::net::Ipv4Addr,
    oip6: std::net::Ipv6Addr,
    iip6: std::net::Ipv6Addr,
    omac: String,
    imac: String,
}

pub struct DevInfo {
    pub name: String,
    pub ns: Option<Namespace>,
    pub index: xdp::nic::NicIndex,
    pub ipv4: std::net::Ipv4Addr,
    pub ipv6: std::net::Ipv6Addr,
    pub mac: [u8; 6],
}

fn get_mac(s: &str) -> String {
    s.split(' ')
        .filter(|s| !s.is_empty())
        .nth(2)
        .unwrap()
        .to_owned()
}

impl TestBed {
    pub fn setup(ns: &'static str, index: u8) -> Self {
        let oname = format!("{ns}-o");
        let iname = format!("{ns}-i");

        ip_exec(&["netns", "add", ns]);
        ip_exec(&[
            "link", "add", "dev", &oname, "type", "veth", "peer", "name", &iname, "netns", ns,
        ]);

        let oip4 = std::net::Ipv4Addr::new(10, 11, index, 1);
        let iip4 = std::net::Ipv4Addr::new(10, 11, index, 2);
        ip_exec(&["addr", "add", "dev", &oname, &format!("{oip4}/24")]);
        ip_exec(&[
            "-n",
            ns,
            "addr",
            "add",
            "dev",
            &iname,
            &format!("{iip4}/24"),
        ]);

        let oip6 = std::net::Ipv6Addr::new(0xfe80, 0xdead, 0xcafe, index as _, 0, 0, 0, 1);
        let iip6 = std::net::Ipv6Addr::new(0xfe80, 0xdead, 0xcafe, index as _, 0, 0, 0, 2);
        ip_exec(&["addr", "add", "dev", &oname, &format!("{oip6}/64")]);
        ip_exec(&[
            "-n",
            ns,
            "addr",
            "add",
            "dev",
            &iname,
            &format!("{iip6}/64"),
        ]);

        exec("ethtool", &["-K", &oname, "rxvlan", "off", "txvlan", "off"]);
        ip_exec(&[
            "netns", "exec", ns, "ethtool", "-K", &iname, "rxvlan", "off", "txvlan", "off",
        ]);
        ip_exec(&["-n", ns, "link", "set", "dev", "lo", "up"]);

        let o = String::from_utf8(
            std::process::Command::new("ip")
                .args(["-br", "-n"])
                .arg(ns)
                .args(["link", "show", "dev", &iname])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let omac = get_mac(&o);
        let o = String::from_utf8(
            std::process::Command::new("ip")
                .args(["-br", "link", "show", "dev", &oname])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let imac = get_mac(&o);

        ip_exec(&[
            "neigh",
            "add",
            &iip4.to_string(),
            "lladdr",
            &imac,
            "dev",
            &oname,
            "nud",
            "permanent",
        ]);
        ip_exec(&[
            "-n",
            ns,
            "neigh",
            "add",
            &oip4.to_string(),
            "lladdr",
            &omac,
            "dev",
            &iname,
            "nud",
            "permanent",
        ]);
        ip_exec(&[
            "neigh",
            "add",
            &iip6.to_string(),
            "lladdr",
            &imac,
            "dev",
            &oname,
            "nud",
            "permanent",
        ]);
        ip_exec(&[
            "-n",
            ns,
            "neigh",
            "add",
            &oip6.to_string(),
            "lladdr",
            &omac,
            "dev",
            &iname,
            "nud",
            "permanent",
        ]);

        ip_exec(&["link", "set", "dev", &oname, "up"]);
        ip_exec(&["-n", ns, "link", "set", "dev", &iname, "up"]);

        ip_exec(&[
            "-n",
            ns,
            "route",
            "add",
            "fe80:dead:cafe::/48",
            "via",
            &oip6.to_string(),
            "dev",
            &iname,
        ]);

        Self {
            namespace: ns,
            oip4,
            iip4,
            oip6,
            iip6,
            omac,
            imac,
        }

        //         NS="pingy-pongy"

        // #OMAC="01:01:01:01:01:01"
        // #IMAC="02:02:02:02:02:02"
        // SUBNET="10.11"
        // OIP="$SUBNET.1.1"
        // IIP="$SUBNET.1.2"

        // ip netns add "$NS"
        // ip link add dev "$NS" type veth peer name veth0 netns "$NS"

        // ip -n "$NS" link set veth0 xdpgeneric obj dummy.o sec xdp
        // ip link set "$NS" xdpgeneric obj boop.o sec xdp

        // IMAC=$(ip -br -n "$NS" link show dev veth0 | awk '{print $3}')
        // OMAC=$(ip -br link show dev $NS | awk '{print $3}')
        // ip link set dev "$NS" up
        // #ip addr add dev "$NS" "fe80::1:1:1:1/64"
        // ip addr add dev "$NS" "$OIP/24"
        // ethtool -K "$NS" rxvlan off txvlan off
        // # Prevent neighbour queries on the link
        // #ip neigh add "fe80::2:2:2:2" lladdr "$IMAC" dev "$NS" nud permanent
        // ip neigh add "169.254.2.0" lladdr "$IMAC" dev "$NS" nud permanent

        // ip -n "$NS" link set dev lo up
        // #ip link set dev veth0 address "$IMAC"
        // ip -n "$NS" link set dev veth0 up

        // #ip -n "$NS" addr add dev veth0 "fe80::2:2:2:2/64"
        // ip -n "$NS" addr add dev veth0 "$IIP/24"
        // ip netns exec "$NS" ethtool -K veth0 rxvlan off txvlan off
        // # Prevent neighbour queries on the link
        // #ip -n "$NS" neigh add "fe80::1:1:1:1" lladdr "$OMAC" dev veth0 nud permanent
        // ip -n "$NS" neigh add "$OIP" lladdr "$OMAC" dev veth0 nud permanent
        // ip -n "$NS" route add "$SUBNET/16" via "$OIP" dev veth0

        // # Add route for whole test subnet, to make it easier to communicate between
        // # namespaces
        // #ip -n "$NS" route add "${IP6_SUBNET}::/$IP6_FULL_PREFIX_SIZE" via "$OUTSIDE_IP6" dev veth0

        // ip netns exec "$NS" ping $OIP
    }

    pub fn up(&self) {
        let ns = self.namespace;
        let oname = format!("{ns}-o");
        let iname = format!("{ns}-i");
        ip_exec(&["link", "set", "dev", &oname, "up"]);
        ip_exec(&["-n", ns, "link", "set", "dev", &iname, "up"]);
    }

    pub fn inside(&self) -> DevInfo {
        let ns = Namespace::new(self.namespace);
        let name = format!("{}-i", self.namespace);
        let index = {
            let _c = ns.enter();
            NicIndex::lookup_by_name(&name).unwrap().unwrap()
        };
        let mut mac = [0u8; 6];
        for (i, v) in self
            .imac
            .split(':')
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .enumerate()
        {
            mac[i] = v;
        }

        DevInfo {
            name,
            ns: Some(ns),
            index,
            ipv4: self.iip4,
            ipv6: self.iip6,
            mac,
        }
    }

    pub fn outside(&self) -> DevInfo {
        let name = format!("{}-o", self.namespace);
        let index = NicIndex::lookup_by_name(&name).unwrap().unwrap();
        let mut mac = [0u8; 6];
        for (i, v) in self
            .omac
            .split(':')
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .enumerate()
        {
            mac[i] = v;
        }

        DevInfo {
            name,
            ns: None,
            index,
            ipv4: self.oip4,
            ipv6: self.oip6,
            mac,
        }
    }
}
