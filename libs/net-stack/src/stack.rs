//! Fixed borrowed sockets and bounded stack turns. The actual service must
//! authenticate clients and authorize every destination before connect/query.
//! Neither these Rust values nor DNS answers are capabilities or TLS trust.
use crate::device::{Frame, Queues, SLOTS};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage},
    socket::{dhcpv4, dns, tcp},
    time::Instant,
    wire::{DnsQueryType, EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Cidr},
};

pub const SOCKETS: usize = 3;
pub const QUERIES: usize = 2;
pub const TCP_BUFFER_BYTES: usize = 4096;
pub const BORROWED_STORAGE_BYTES: usize = core::mem::size_of::<[Frame; SLOTS]>() * 2
    + core::mem::size_of::<[SocketStorage<'static>; SOCKETS]>()
    + core::mem::size_of::<[Option<dns::DnsQuery>; QUERIES]>()
    + TCP_BUFFER_BYTES * 2;
const _: () = assert!(BORROWED_STORAGE_BYTES <= 48 * 1024);
const _: () = assert!(core::mem::size_of::<Stack<'static>>() <= 8 * 1024);

/// Storage is supplied/charged by the actual owner; no hidden allocation. Only
/// recycle it after old service/session/accepted-buffer references are retired.
pub struct Buffers<'a> {
    pub receive: &'a mut [Frame; SLOTS],
    pub transmit: &'a mut [Frame; SLOTS],
    pub sockets: &'a mut [SocketStorage<'a>; SOCKETS],
    pub queries: &'a mut [Option<dns::DnsQuery>; QUERIES],
    pub tcp_receive: &'a mut [u8; TCP_BUFFER_BYTES],
    pub tcp_transmit: &'a mut [u8; TCP_BUFFER_BYTES],
}

/// Fixed private backing suitable for one measured ELF owner. This type
/// contains storage only, never caps or provider trust. Its owner must enforce
/// one initialization/borrow lifetime and charge its actual mapped pages.
pub struct Storage<'a> {
    receive: [Frame; SLOTS],
    transmit: [Frame; SLOTS],
    sockets: [SocketStorage<'a>; SOCKETS],
    queries: [Option<dns::DnsQuery>; QUERIES],
    tcp_receive: [u8; TCP_BUFFER_BYTES],
    tcp_transmit: [u8; TCP_BUFFER_BYTES],
}
impl<'a> Storage<'a> {
    pub const EMPTY: Self = Self {
        receive: [const { Frame::EMPTY }; SLOTS],
        transmit: [const { Frame::EMPTY }; SLOTS],
        sockets: [const { SocketStorage::EMPTY }; SOCKETS],
        queries: [const { None }; QUERIES],
        tcp_receive: [0; TCP_BUFFER_BYTES],
        tcp_transmit: [0; TCP_BUFFER_BYTES],
    };
    pub fn buffers(&'a mut self) -> Buffers<'a> {
        Buffers {
            receive: &mut self.receive,
            transmit: &mut self.transmit,
            sockets: &mut self.sockets,
            queries: &mut self.queries,
            tcp_receive: &mut self.tcp_receive,
            tcp_transmit: &mut self.tcp_transmit,
        }
    }
}
const _: () = assert!(core::mem::size_of::<Storage<'static>>() == BORROWED_STORAGE_BYTES);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Time,
    Quarantined,
    Capacity,
    Query,
    QueryPending,
    StaleQuery,
    Counter,
    Connect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Cidr,
    pub router: Option<Ipv4Address>,
    pub dns: [Option<Ipv4Address>; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpStatus {
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
}

/// Local fresh reference, not authority; bind the real service incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query {
    incarnation: u64,
    sequence: u64,
}

struct PendingQuery {
    ticket: Query,
    handle: dns::QueryHandle,
}

pub struct Stack<'a> {
    device: Queues<'a>,
    interface: Interface,
    sockets: SocketSet<'a>,
    dhcp: SocketHandle,
    dns: SocketHandle,
    tcp: SocketHandle,
    lease: Option<Lease>,
    incarnation: u64,
    query_sequence: u64,
    pending: [Option<PendingQuery>; QUERIES],
    last_millis: u64,
    failed: bool,
}

impl<'a> Stack<'a> {
    /// `seed` must come from the actual approved random service for security
    /// runs. A number alone cannot prove entropy; deterministic tests stay tests.
    pub fn new(
        incarnation: u64,
        mac: [u8; 6],
        seed: u64,
        now_millis: u64,
        buffers: Buffers<'a>,
    ) -> Result<Self, Error> {
        if incarnation == 0 || mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(Error::Identity);
        }
        let now = Self::instant(now_millis)?;
        let mut device = Queues::new(buffers.receive, buffers.transmit);
        let mut config = Config::new(EthernetAddress(mac).into());
        config.random_seed = seed;
        let interface = Interface::new(config, &mut device, now);
        for slot in buffers.sockets.iter_mut() {
            *slot = SocketStorage::EMPTY;
        }
        for query in buffers.queries.iter_mut() {
            *query = None;
        }
        buffers.tcp_receive.fill(0);
        buffers.tcp_transmit.fill(0);
        let mut sockets = SocketSet::new(&mut buffers.sockets[..]);
        let dhcp = sockets.add(dhcpv4::Socket::new());
        let dns = sockets.add(dns::Socket::new(&[], &mut buffers.queries[..]));
        let tcp = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(&mut buffers.tcp_receive[..]),
            tcp::SocketBuffer::new(&mut buffers.tcp_transmit[..]),
        ));
        Ok(Self {
            device,
            interface,
            sockets,
            dhcp,
            dns,
            tcp,
            lease: None,
            incarnation,
            query_sequence: 0,
            pending: [const { None }; QUERIES],
            last_millis: now_millis,
            failed: false,
        })
    }

    fn instant(millis: u64) -> Result<Instant, Error> {
        Ok(Instant::from_millis(
            i64::try_from(millis).map_err(|_| Error::Time)?,
        ))
    }
    fn active(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Quarantined)
        } else {
            Ok(())
        }
    }
    pub fn device(&mut self) -> &mut Queues<'a> {
        &mut self.device
    }
    pub fn lease(&self) -> Option<Lease> {
        self.lease
    }

    /// Exactly one bounded ingress attempt and one bounded egress pass. The
    /// actual scheduler owner yields between turns and enforces operation bounds.
    pub fn turn(&mut self, now_millis: u64) -> Result<(), Error> {
        self.active()?;
        let now = match Self::instant(now_millis) {
            Ok(now) if now_millis >= self.last_millis => now,
            _ => {
                self.failed = true;
                self.device.quarantine();
                return Err(Error::Time);
            }
        };
        self.last_millis = now_millis;
        self.interface.poll_maintenance(now);
        self.interface
            .poll_ingress_single(now, &mut self.device, &mut self.sockets);
        self.update_lease()?;
        self.interface
            .poll_egress(now, &mut self.device, &mut self.sockets);
        Ok(())
    }

    fn update_lease(&mut self) -> Result<(), Error> {
        let event = match self.sockets.get_mut::<dhcpv4::Socket>(self.dhcp).poll() {
            None => return Ok(()),
            Some(dhcpv4::Event::Deconfigured) => None,
            Some(dhcpv4::Event::Configured(config)) => {
                let mut dns = [None; 2];
                for (out, address) in dns.iter_mut().zip(config.dns_servers.iter()) {
                    *out = Some(*address);
                }
                Some(Lease {
                    address: config.address,
                    router: config.router,
                    dns,
                })
            }
        };
        self.interface.update_ip_addrs(|addresses| {
            addresses.clear();
            if let Some(lease) = event {
                let _ = addresses.push(IpCidr::Ipv4(lease.address));
            }
        });
        self.interface.routes_mut().remove_default_ipv4_route();
        if let Some(router) = event.and_then(|lease| lease.router)
            && self
                .interface
                .routes_mut()
                .add_default_ipv4_route(router)
                .is_err()
        {
            self.failed = true;
            self.device.quarantine();
            return Err(Error::Capacity);
        }
        let mut addresses = [IpAddress::Ipv4(Ipv4Address::UNSPECIFIED); 2];
        let mut count = 0;
        if let Some(lease) = event {
            for address in lease.dns.into_iter().flatten() {
                addresses[count] = IpAddress::Ipv4(address);
                count += 1;
            }
        }
        self.sockets
            .get_mut::<dns::Socket>(self.dns)
            .update_servers(&addresses[..count]);
        self.lease = event;
        Ok(())
    }

    /// Trusted service call only: real capability/destination checks precede it.
    pub fn connect(&mut self, remote: IpEndpoint, local_port: u16) -> Result<(), Error> {
        self.active()?;
        self.sockets
            .get_mut::<tcp::Socket>(self.tcp)
            .connect(self.interface.context(), remote, local_port)
            .map_err(|_| Error::Connect)
    }
    /// The actual service checks its fixed destination scope before calling.
    pub fn connect_v4(
        &mut self,
        address: [u8; 4],
        port: u16,
        local_port: u16,
    ) -> Result<(), Error> {
        self.connect(
            IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::from(address)), port),
            local_port,
        )
    }
    pub fn tcp_status(&mut self) -> Result<TcpStatus, Error> {
        Ok(match self.tcp()?.state() {
            tcp::State::Closed => TcpStatus::Closed,
            tcp::State::Listen => TcpStatus::Listen,
            tcp::State::SynSent => TcpStatus::SynSent,
            tcp::State::SynReceived => TcpStatus::SynReceived,
            tcp::State::Established => TcpStatus::Established,
            tcp::State::FinWait1 => TcpStatus::FinWait1,
            tcp::State::FinWait2 => TcpStatus::FinWait2,
            tcp::State::CloseWait => TcpStatus::CloseWait,
            tcp::State::Closing => TcpStatus::Closing,
            tcp::State::LastAck => TcpStatus::LastAck,
            tcp::State::TimeWait => TcpStatus::TimeWait,
        })
    }
    /// None is ordinary backpressure; Some(n) is exactly the queued prefix.
    pub fn tcp_send(&mut self, data: &[u8]) -> Result<Option<usize>, Error> {
        let socket = self.tcp()?;
        if !socket.can_send() {
            return Ok(None);
        }
        socket
            .send_slice(data)
            .map(Some)
            .map_err(|_| Error::Connect)
    }
    /// None is pending; Some(0) is actual EOF, not a fabricated successful read.
    pub fn tcp_receive(&mut self, data: &mut [u8]) -> Result<Option<usize>, Error> {
        let socket = self.tcp()?;
        if !socket.can_recv() {
            return Ok(if socket.may_recv() { None } else { Some(0) });
        }
        socket
            .recv_slice(data)
            .map(Some)
            .map_err(|_| Error::Connect)
    }
    pub fn close_tcp(&mut self) -> Result<(), Error> {
        self.tcp()?.close();
        Ok(())
    }
    /// Consume one real DNS result only if it includes the independently fixed
    /// allowed address. A DNS answer never expands the destination scope.
    pub fn query_result_matches(&mut self, ticket: Query, address: [u8; 4]) -> Result<bool, Error> {
        let expected = IpAddress::Ipv4(Ipv4Address::from(address));
        self.query_result(ticket)
            .map(|rows| rows.into_iter().flatten().any(|value| value == expected))
    }
    /// Actual diagnostic results only. The service separately authorizes its
    /// fixed transfer destination; answers never expand that authority.
    pub fn query_result_v4(&mut self, ticket: Query) -> Result<[Option<[u8; 4]>; 2], Error> {
        self.query_result(ticket).map(|rows| {
            rows.map(|row| {
                row.map(|address| match address {
                    IpAddress::Ipv4(address) => address.octets(),
                })
            })
        })
    }

    /// Actual service owns per-client delivery and cancellation; this borrowed
    /// fixed socket cannot grow the SocketSet or alter the interface clock.
    pub fn tcp(&mut self) -> Result<&mut tcp::Socket<'a>, Error> {
        self.active()?;
        Ok(self.sockets.get_mut(self.tcp))
    }

    pub fn query(&mut self, name: &str) -> Result<Query, Error> {
        self.active()?;
        let slot = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let sequence = self.query_sequence.checked_add(1).ok_or(Error::Counter)?;
        let handle = self
            .sockets
            .get_mut::<dns::Socket>(self.dns)
            .start_query(self.interface.context(), name, DnsQueryType::A)
            .map_err(|_| Error::Query)?;
        let ticket = Query {
            incarnation: self.incarnation,
            sequence,
        };
        self.pending[slot] = Some(PendingQuery { ticket, handle });
        self.query_sequence = sequence;
        Ok(ticket)
    }

    fn query_slot(&self, ticket: Query) -> Result<usize, Error> {
        self.pending
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.ticket == ticket))
            .ok_or(Error::StaleQuery)
    }

    pub fn query_result(&mut self, ticket: Query) -> Result<[Option<IpAddress>; 2], Error> {
        self.active()?;
        let slot = self.query_slot(ticket)?;
        let handle = self.pending[slot].as_ref().unwrap().handle;
        match self
            .sockets
            .get_mut::<dns::Socket>(self.dns)
            .get_query_result(handle)
        {
            Ok(result) => {
                self.pending[slot] = None;
                let mut addresses = [None; 2];
                for (out, address) in addresses.iter_mut().zip(result.iter()) {
                    *out = Some(*address);
                }
                Ok(addresses)
            }
            Err(dns::GetQueryResultError::Pending) => Err(Error::QueryPending),
            Err(dns::GetQueryResultError::Failed) => {
                self.pending[slot] = None;
                Err(Error::Query)
            }
        }
    }

    pub fn cancel_query(&mut self, ticket: Query) -> Result<(), Error> {
        self.active()?;
        let slot = self.query_slot(ticket)?;
        let pending = self.pending[slot].take().unwrap();
        self.sockets
            .get_mut::<dns::Socket>(self.dns)
            .cancel_query(pending.handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
