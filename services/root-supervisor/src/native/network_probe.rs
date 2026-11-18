//! Explicit negative fixture commands. The existing affine client, original
//! aggregate cut, ordinary scoped child cuts, and resident Root owner remain
//! the only network authority. Waiting on the host never pumps network reads.
#[cfg(not(feature = "native-network-negative"))]
pub(super) struct Probe;
#[cfg(not(feature = "native-network-negative"))]
impl Probe {
    pub(super) const fn new() -> Self {
        Self
    }
}
#[cfg(feature = "native-network-negative")]
mod actual {
    use super::super::*;
    use ev_root_supervisor::native_network::transfer::Transfer;
    use ev_root_supervisor::native_network::{Phase as NetworkPhase, client::Error};
    const PENDING: &[u8] = b"GET /pending HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n";
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Phase {
        Dormant,
        Endurance,
        Close,
        Closed,
        BadAddress,
        BadPort,
        BadName,
        Followup,
        Connect,
        Connecting,
        Write,
        Read,
        WaitingHost,
        WaitingRecovery,
        Done,
        Failed,
    }
    pub(in super::super) struct Probe {
        phase: Phase,
        cut: u64,
        after: u64,
        destination: bool,
        written: usize,
        transfer: Transfer,
        sample_after: u64,
    }
    impl Probe {
        pub(in super::super) const fn new() -> Self {
            Self {
                phase: Phase::Dormant,
                cut: 0,
                after: 0,
                destination: false,
                written: 0,
                transfer: Transfer::new(),
                sample_after: 0,
            }
        }
    }
    impl Root<'_> {
        pub(in super::super) fn native_negative_command(&mut self, command: Command) -> bool {
            if command == Command::NetEnduranceStop {
                let p = &mut self.native.as_mut().unwrap().network_probe;
                if p.phase == Phase::Endurance {
                    p.phase = Phase::Done;
                }
                return true;
            }
            if command == Command::NetEndurance {
                let n = self.native.as_ref().unwrap();
                if n.network_probe.phase != Phase::Dormant
                    || n.running.is_none()
                    || n.starting
                    || !n.app_settled
                    || !n.network_transfer.succeeded()
                    || n.network.phase() != NetworkPhase::Running
                    || n.state.content_busy()
                    || n.state.transition_pending()
                    || n.note_reply.is_some()
                    || n.transition.is_some()
                    || n.preparing.is_some()
                {
                    return true;
                }
                let tick = now();
                let Some(cut) = tick.checked_add(900_000).filter(|v| *v != u64::MAX) else {
                    return true;
                };
                let r = rt::send(self.channels[Channel::AppControl.index()], *b"EVNABUS1");
                if r.status != 0 || r.value != 0 || r.capability != 0 {
                    return true;
                }
                let p = &mut self.native.as_mut().unwrap().network_probe;
                p.phase = Phase::Endurance;
                p.cut = cut;
                p.after = 0;
                p.sample_after = 0;
                return true;
            }

            if !matches!(
                command,
                Command::NetDestination
                    | Command::NetPending
                    | Command::NetDriverStop
                    | Command::NetServiceStop
            ) {
                return false;
            }
            if matches!(command, Command::NetDestination | Command::NetPending) {
                let n = self.native.as_ref().unwrap();
                if n.network_probe.phase != Phase::Dormant
                    || !n.network_transfer.succeeded()
                    || n.network.phase() != NetworkPhase::Running
                {
                    return true;
                }
                let Some(cut) = now().checked_add(8192).filter(|v| *v != u64::MAX) else {
                    return true;
                };
                let r = rt::call4(syscall::NETWORK_NEGATIVE_PROBE, 3, 0, 0, cut);
                if r.status != 0 || r.value != 0 || r.capability != 0 || r.serial != 0 {
                    return true;
                }
                let p = &mut self.native.as_mut().unwrap().network_probe;
                p.cut = cut;
                p.destination = command == Command::NetDestination;
                p.phase = Phase::Close;
                return true;
            }
            let n = self.native.as_ref().unwrap();
            if n.network_probe.phase != Phase::WaitingHost || now() >= n.network_probe.cut {
                return true;
            }
            let aggregate = n.network_probe.cut;
            let operation = if command == Command::NetDriverStop {
                1
            } else {
                2
            };
            let r = rt::call4(syscall::NETWORK_NEGATIVE_PROBE, operation, 0, 0, aggregate);
            if r.status != 0 || r.value != 0 || r.capability != 0 || r.serial != 0 {
                return true;
            }
            let tick = now();
            let cut = tick.saturating_add(1024).min(aggregate);
            let n = self.native.as_mut().unwrap();
            // No accepted call is repeated. The captured Driver RECEIVE_RPC
            // hook stops the selected actual process inside this nested call.
            n.network_probe.phase = match n.network_client.shutdown_begin(aggregate, tick, cut) {
                Err(
                    Error::Transport | Error::Remote(ev_net_driver::control::Status::Uncertain),
                ) => Phase::WaitingRecovery,
                _ => Phase::Failed,
            };
            true
        }
        pub(in super::super) fn native_negative_tick(&mut self) -> bool {
            let n = self.native.as_mut().unwrap();
            let p = &mut n.network_probe;
            if matches!(
                p.phase,
                Phase::Dormant | Phase::Done | Phase::Failed | Phase::WaitingRecovery
            ) {
                return false;
            }
            let tick = now();
            if tick >= p.cut {
                p.phase = Phase::Failed;
                return false;
            }
            if p.phase == Phase::Endurance {
                if tick >= p.after {
                    let _ = rt::send(self.channels[Channel::ShellControl.index()], *b"EVNWORK1");
                    p.after = tick.saturating_add(64);
                }
                if tick >= p.sample_after {
                    let r = rt::call4(
                        syscall::NETWORK_NEGATIVE_PROBE,
                        4,
                        0,
                        0,
                        tick.saturating_add(512),
                    );
                    if r.status != 0 || r.value != 0 || r.capability != 0 || r.serial != 0 {
                        p.phase = Phase::Failed;
                        return false;
                    }
                    p.sample_after = tick.saturating_add(8192);
                }
                // Finite CPU work in this actual Root process, separate from
                // accepted IO. Normal Root owner/Note turns continue afterward.
                let mut value = 1u64;
                for _ in 0..1_048_576 {
                    value = value.wrapping_mul(6364136223846793005).wrapping_add(1);
                    core::hint::black_box(value);
                }
                return false;
            }
            // Preserve UI and local Note turns while a real TCP read is pending.
            if p.phase == Phase::WaitingHost || tick < p.after {
                return false;
            }
            let result = Self::negative_step(n, tick);
            if result.is_err() {
                self.native.as_mut().unwrap().network_probe.phase = Phase::Failed;
            }
            true
        }
        fn negative_step(n: &mut Controller<'_>, tick: u64) -> Result<(), ()> {
            let policy = n.packages.catalogue().network().ok_or(())?.network_policy();
            let p = &mut n.network_probe;
            let client = &mut n.network_client;
            let cut = tick.checked_add(1024).ok_or(())?.min(p.cut);
            p.after = tick.checked_add(64).ok_or(())?;
            match p.phase {
                Phase::Close => {
                    client.close(tick, cut).map_err(|_| ())?;
                    p.phase = Phase::Closed;
                }
                Phase::Closed => {
                    let (_, tcp, configured) = client.status(tick, cut).map_err(|_| ())?;
                    if configured && tcp == 0 {
                        p.phase = if p.destination {
                            Phase::BadAddress
                        } else {
                            Phase::Connect
                        };
                    }
                }
                Phase::BadAddress | Phase::BadPort => {
                    let mut dest = [0; 6];
                    dest[..4].copy_from_slice(&policy.allowed_ipv4);
                    dest[4..].copy_from_slice(&policy.remote_port.to_le_bytes());
                    if p.phase == Phase::BadAddress {
                        dest[3] ^= 1;
                    } else {
                        dest[4] ^= 1;
                    }
                    client
                        .probe_forbidden_destination(dest, tick, cut)
                        .map_err(|_| ())?;
                    p.phase = if p.phase == Phase::BadAddress {
                        Phase::BadPort
                    } else {
                        Phase::BadName
                    };
                }
                Phase::BadName => {
                    // Refused is the only expected result. Neither DNS nor a
                    // supplied name can change the immutable TCP destination.
                    if !matches!(
                        client.resolve("forbidden.invalid", tick, cut),
                        Err(Error::Remote(ev_net_driver::control::Status::Refused))
                    ) {
                        return Err(());
                    }
                    p.transfer.begin(tick, p.cut).map_err(|_| ())?;
                    p.phase = Phase::Followup;
                }
                Phase::Followup => {
                    p.transfer.step(client, policy, tick).map_err(|_| ())?;
                    if p.transfer.finished() {
                        if !p.transfer.succeeded() {
                            return Err(());
                        }
                        p.phase = Phase::Done;
                    }
                }
                Phase::Connect => {
                    client.connect(policy, tick, cut).map_err(|_| ())?;
                    p.phase = Phase::Connecting;
                }
                Phase::Connecting => {
                    let (_, tcp, configured) = client.status(tick, cut).map_err(|_| ())?;
                    if configured && tcp == 4 {
                        p.phase = Phase::Write;
                    }
                }
                Phase::Write => {
                    if let Some(written) = client
                        .write(&PENDING[p.written..], tick, cut)
                        .map_err(|_| ())?
                    {
                        p.written += written;
                        if p.written == PENDING.len() {
                            p.phase = Phase::Read;
                        }
                    }
                }
                Phase::Read => {
                    if client.read(tick, cut).map_err(|_| ())?.is_some() {
                        return Err(());
                    }
                    p.phase = Phase::WaitingHost;
                }
                _ => return Err(()),
            }
            Ok(())
        }
    }
}
#[cfg(feature = "native-network-negative")]
pub(super) use actual::Probe;
