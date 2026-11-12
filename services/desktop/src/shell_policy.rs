//! Actual adapters must authenticate Root/Input endpoints, retain the requester
//! incarnation, wait for real Present completion, and obtain the real Input
//! barrier. This reducer itself issues no syscall or authority. Its selection
//! request must still pass the separate current-object/live-recipient handoff.
use ev_graphics::shell::{FileChoice, Screen};
use ev_input::{BarrierReply, Key, KeyEvent, protocol::FreshGate};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    State,
    Stale,
    Counter,
    Input,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Render {
    pub frame: u32,
    pub screen: Screen,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Launch,
    Forward(KeyEvent),
    Select {
        request: u32,
        app_epoch: u64,
        file: FileChoice,
    },
    Cancel {
        request: u32,
    },
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    pub render: Option<Render>,
    pub command: Option<Command>,
    pub barrier_after_frame: Option<u32>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootEvent {
    AppStarted { epoch: u64 },
    AppRestored { epoch: u64 },
    AppStopped { epoch: u64 },
    PickFile { request: u32, app_epoch: u64 },
    FileDelivered { request: u32, app_epoch: u64 },
    FileRefused { request: u32, app_epoch: u64 },
    InputRestarted,
    LaunchRefused,
    OwnerFilePending { request: u32, app_epoch: u64 },
    OwnerFileDelivered { request: u32, app_epoch: u64 },
    OwnerFileRefused { request: u32, app_epoch: u64 },
    ManagedFilePending { request: u32, app_epoch: u64 },
    ManagedFileDelivered { request: u32, app_epoch: u64 },
    ManagedFileRefused { request: u32, app_epoch: u64 },
    OwnerActionPending { serial: u32, app_epoch: u64 },
    OwnerActionDone { serial: u32, app_epoch: u64 },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    OwnerFile,
    ManagedFile,
    OwnerAction,
}
struct Managed {
    kind: PendingKind,
    request: u32,
    app_epoch: u64,
}
struct Picker {
    request: u32,
    app_epoch: u64,
    selected: FileChoice,
    gate: Option<FreshGate>,
    awaiting_display: Option<u32>,
    awaiting_barrier: Option<u32>,
    submitted: bool,
}
pub struct Policy {
    screen: Screen,
    frame: u32,
    last_key: u32,
    last_request: u32,
    app_epoch: Option<u64>,
    launching: bool,
    focused_app: bool,
    picker: Option<Picker>,
    managed: Option<Managed>,
}
impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}
impl Policy {
    pub const fn new() -> Self {
        Self {
            screen: Screen::Home,
            frame: 0,
            last_key: 0,
            last_request: 0,
            app_epoch: None,
            launching: false,
            focused_app: false,
            picker: None,
            managed: None,
        }
    }
    pub fn screen(&self) -> Screen {
        self.screen
    }
    fn render(&self, screen: Screen) -> Result<Render, Error> {
        let frame = self
            .frame
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .ok_or(Error::Counter)?;
        Ok(Render { frame, screen })
    }
    fn publish(&mut self, render: Render) -> Effects {
        self.frame = render.frame;
        self.screen = render.screen;
        Effects {
            render: Some(render),
            ..Effects::default()
        }
    }
    pub fn initial(&mut self) -> Result<Effects, Error> {
        let r = self.render(Screen::Home)?;
        Ok(self.publish(r))
    }
    /// A Root message is accepted only through the adapter's fixed Root channel.
    /// Epochs/requests correlate state and are not ProcessCONTROL or File caps.
    pub fn root(&mut self, event: RootEvent) -> Result<Effects, Error> {
        match event {
            RootEvent::LaunchRefused => {
                if !self.launching || self.app_epoch.is_some() || self.picker.is_some() {
                    return Err(Error::Stale);
                }
                let r = self.render(Screen::Home)?;
                self.launching = false;
                self.focused_app = false;
                Ok(self.publish(r))
            }
            RootEvent::AppRestored { epoch } => {
                if epoch == 0
                    || epoch == u64::MAX
                    || self.app_epoch.is_some()
                    || self.picker.is_some()
                {
                    return Err(Error::State);
                }
                let r = self.render(Screen::AppRunning)?;
                self.app_epoch = Some(epoch);
                self.launching = false;
                self.focused_app = true;
                Ok(self.publish(r))
            }
            RootEvent::AppStarted { epoch } => {
                if epoch == 0 || epoch == u64::MAX || !self.launching || self.app_epoch.is_some() {
                    return Err(Error::State);
                }
                let r = self.render(Screen::AppRunning)?;
                self.app_epoch = Some(epoch);
                self.launching = false;
                self.focused_app = true;
                Ok(self.publish(r))
            }
            RootEvent::AppStopped { epoch } => {
                if self.app_epoch != Some(epoch) {
                    return Err(Error::Stale);
                }
                let r = self.render(Screen::AppStopped)?;
                let old = self.picker.take();
                self.managed = None;
                self.app_epoch = None;
                self.focused_app = false;
                self.launching = false;
                let mut effects = self.publish(r);
                effects.command = old.map(|p| Command::Cancel { request: p.request });
                Ok(effects)
            }
            RootEvent::PickFile { request, app_epoch } => {
                if self.app_epoch != Some(app_epoch)
                    || self.picker.is_some()
                    || self.managed.is_some()
                    || request == 0
                    || request == u32::MAX
                    || request <= self.last_request
                {
                    return Err(Error::Stale);
                }
                let r = self.render(Screen::Picker {
                    selected: FileChoice::Notes,
                })?;
                self.last_request = request;
                self.focused_app = false;
                self.picker = Some(Picker {
                    request,
                    app_epoch,
                    selected: FileChoice::Notes,
                    gate: None,
                    awaiting_display: Some(r.frame),
                    awaiting_barrier: None,
                    submitted: false,
                });
                Ok(self.publish(r))
            }
            RootEvent::FileDelivered { request, app_epoch }
            | RootEvent::FileRefused { request, app_epoch } => {
                if !self.picker.as_ref().is_some_and(|p| {
                    p.request == request && p.app_epoch == app_epoch && p.submitted
                }) || self.app_epoch != Some(app_epoch)
                {
                    return Err(Error::Stale);
                }
                let r = self.render(Screen::AppRunning)?;
                self.picker = None;
                self.focused_app = true;
                Ok(self.publish(r))
            }
            RootEvent::InputRestarted => {
                let screen = if self.app_epoch.is_some() {
                    Screen::AppRunning
                } else {
                    Screen::Home
                };
                let r = self.render(screen)?;
                let old = self.picker.take();
                self.managed = None;
                self.last_key = 0;
                self.focused_app = self.app_epoch.is_some();
                let mut effects = self.publish(r);
                effects.command = old.map(|p| Command::Cancel { request: p.request });
                Ok(effects)
            }
            RootEvent::OwnerFilePending { request, app_epoch } => {
                if self.app_epoch != Some(app_epoch)
                    || self.managed.is_some()
                    || !self.picker.as_ref().is_some_and(|p| {
                        p.request == request && p.app_epoch == app_epoch && !p.submitted
                    })
                {
                    return Err(Error::Stale);
                }
                let render = self.render(Screen::AppRunning)?;
                self.picker = None;
                self.focused_app = false;
                self.managed = Some(Managed {
                    kind: PendingKind::OwnerFile,
                    request,
                    app_epoch,
                });
                Ok(self.publish(render))
            }
            RootEvent::ManagedFilePending { request, app_epoch } => {
                if self.app_epoch != Some(app_epoch)
                    || self.picker.is_some()
                    || self.managed.is_some()
                    || request == 0
                    || request == u32::MAX
                    || request <= self.last_request
                {
                    return Err(Error::Stale);
                }
                let render = self.render(Screen::AppRunning)?;
                self.last_request = request;
                self.focused_app = false;
                self.managed = Some(Managed {
                    kind: PendingKind::ManagedFile,
                    request,
                    app_epoch,
                });
                Ok(self.publish(render))
            }
            RootEvent::OwnerActionPending { serial, app_epoch } => {
                if self.app_epoch != Some(app_epoch)
                    || self.managed.is_some()
                    || serial == 0
                    || serial == u32::MAX
                {
                    return Err(Error::Stale);
                }
                let render = self.render(Screen::AppRunning)?;
                self.picker = None;
                self.focused_app = false;
                self.managed = Some(Managed {
                    kind: PendingKind::OwnerAction,
                    request: serial,
                    app_epoch,
                });
                Ok(self.publish(render))
            }
            RootEvent::OwnerFileDelivered { request, app_epoch }
            | RootEvent::OwnerFileRefused { request, app_epoch } => {
                self.managed_done(PendingKind::OwnerFile, request, app_epoch)
            }
            RootEvent::ManagedFileDelivered { request, app_epoch }
            | RootEvent::ManagedFileRefused { request, app_epoch } => {
                self.managed_done(PendingKind::ManagedFile, request, app_epoch)
            }
            RootEvent::OwnerActionDone { serial, app_epoch } => {
                self.managed_done(PendingKind::OwnerAction, serial, app_epoch)
            }
        }
    }
    fn managed_done(
        &mut self,
        kind: PendingKind,
        request: u32,
        app_epoch: u64,
    ) -> Result<Effects, Error> {
        if self.app_epoch != Some(app_epoch)
            || !self
                .managed
                .as_ref()
                .is_some_and(|p| p.kind == kind && p.request == request && p.app_epoch == app_epoch)
        {
            return Err(Error::Stale);
        }
        let render = self.render(Screen::AppRunning)?;
        self.managed = None;
        self.focused_app = true;
        Ok(self.publish(render))
    }
    /// Call only after the exact protected Present reply, never after enqueue or
    /// a user marker. An old/double reply cannot arm a newly displayed choice.
    pub fn displayed(&mut self, frame: u32) -> Result<Effects, Error> {
        if frame != self.frame {
            return Err(Error::Stale);
        }
        let Some(p) = self.picker.as_mut() else {
            return Ok(Effects::default());
        };
        if p.submitted {
            // A fresh approval emits an Opening redraw before the adapter sends
            // Select. Its actual Present still needs an acknowledgement, but
            // the completed selection must never acquire another input gate.
            return if self.screen
                == (Screen::Opening {
                    selected: p.selected,
                }) {
                Ok(Effects::default())
            } else {
                Err(Error::State)
            };
        }
        if p.awaiting_display != Some(frame) {
            return Err(Error::Stale);
        }
        p.awaiting_display = None;
        p.awaiting_barrier = Some(frame);
        Ok(Effects {
            barrier_after_frame: Some(frame),
            ..Effects::default()
        })
    }
    /// The adapter cancels on Input replacement and drains obsolete sender
    /// messages before rebinding. Barrier flags remain freshness, not consent.
    pub fn barrier(&mut self, frame: u32, reply: BarrierReply) -> Result<(), Error> {
        let p = self.picker.as_mut().ok_or(Error::State)?;
        if p.submitted || p.awaiting_barrier != Some(frame) || frame != self.frame {
            return Err(Error::Stale);
        }
        let mut snapshot = reply;
        snapshot.sequence = snapshot.sequence.max(self.last_key);
        let gate = FreshGate::after_barrier(snapshot).map_err(|_| Error::Input)?;
        p.awaiting_barrier = None;
        p.gate = Some(gate);
        Ok(())
    }
    /// After a new Input incarnation or Shell replacement, the actual adapter
    /// drains Input after its protected redraw. No picker approval survives.
    /// Old queued frames remain untrusted data and cannot move focus or launch.
    pub fn input_drained(&mut self, reply: BarrierReply) -> Result<(), Error> {
        if self.picker.is_some() {
            return Err(Error::State);
        }
        reply.encode().map_err(|_| Error::Input)?;
        self.last_key = self.last_key.max(reply.sequence);
        Ok(())
    }
    pub fn key(&mut self, event: KeyEvent) -> Result<Effects, Error> {
        event.encode().map_err(|_| Error::Input)?;
        if event.sequence <= self.last_key {
            return Err(Error::Stale);
        }
        // Reserve a visual revision before consuming a key that may change it.
        let next = self.render(self.screen)?;
        self.last_key = event.sequence;
        if self.managed.is_some() {
            return Ok(Effects::default());
        }
        if let Some(p) = self.picker.as_mut() {
            if p.submitted {
                return Ok(Effects::default());
            }
            let Some(gate) = p.gate.as_mut() else {
                return Ok(Effects::default());
            };
            let Some(key) = gate.observe(event).map_err(|_| Error::Input)? else {
                return Ok(Effects::default());
            };
            return match key {
                Key::Tab | Key::Up | Key::Down => {
                    p.selected = p.selected.next();
                    p.gate = None;
                    p.awaiting_display = Some(next.frame);
                    p.awaiting_barrier = None;
                    let screen = Screen::Picker {
                        selected: p.selected,
                    };
                    Ok(self.publish(Render { screen, ..next }))
                }
                Key::Enter => {
                    let command = Command::Select {
                        request: p.request,
                        app_epoch: p.app_epoch,
                        file: p.selected,
                    };
                    let screen = Screen::Opening {
                        selected: p.selected,
                    };
                    p.submitted = true;
                    p.gate = None;
                    let mut effects = self.publish(Render { screen, ..next });
                    effects.command = Some(command);
                    Ok(effects)
                }
                Key::Escape => {
                    let request = p.request;
                    self.picker = None;
                    self.focused_app = true;
                    let mut effects = self.publish(Render {
                        screen: Screen::AppRunning,
                        ..next
                    });
                    effects.command = Some(Command::Cancel { request });
                    Ok(effects)
                }
            };
        }
        if self.focused_app && self.app_epoch.is_some() {
            if event.key == Key::Escape {
                self.focused_app = false;
                return Ok(self.publish(Render {
                    screen: Screen::Home,
                    ..next
                }));
            }
            return Ok(Effects {
                command: Some(Command::Forward(event)),
                ..Effects::default()
            });
        }
        if event.key == Key::Enter && !self.launching {
            if self.app_epoch.is_some() {
                self.focused_app = true;
                return Ok(self.publish(Render {
                    screen: Screen::AppRunning,
                    ..next
                }));
            }
            self.launching = true;
            return Ok(Effects {
                command: Some(Command::Launch),
                ..Effects::default()
            });
        }
        if event.key == Key::Escape && self.app_epoch.is_none() {
            return Ok(self.publish(Render {
                screen: Screen::Home,
                ..next
            }));
        }
        Ok(Effects::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_input::EnterState;
    fn key(sequence: u32, k: Key, eligible: bool) -> KeyEvent {
        KeyEvent {
            key: k,
            sequence,
            release_known: k == Key::Enter && eligible,
            approval_ready: k == Key::Enter && eligible,
        }
    }
    #[test]
    fn refused_missing_install_clears_only_a_pending_launch() {
        let mut p = Policy::new();
        p.initial().unwrap();
        assert_eq!(p.root(RootEvent::LaunchRefused), Err(Error::Stale));
        assert_eq!(
            p.key(key(1, Key::Enter, true)).unwrap().command,
            Some(Command::Launch)
        );
        let refused = p.root(RootEvent::LaunchRefused).unwrap();
        assert_eq!(refused.render.unwrap().screen, Screen::Home);
        assert_eq!(refused.command, None);
        assert_eq!(p.root(RootEvent::LaunchRefused), Err(Error::Stale));
        assert_eq!(
            p.key(key(2, Key::Enter, true)).unwrap().command,
            Some(Command::Launch)
        );
        p.root(RootEvent::AppStarted { epoch: 1 }).unwrap();
        assert_eq!(p.root(RootEvent::LaunchRefused), Err(Error::Stale));
        assert_eq!(p.screen(), Screen::AppRunning);
    }
    #[test]
    fn authenticated_owner_launch_can_complete_a_concurrent_home_launch() {
        let mut p = Policy::new();
        p.initial().unwrap();
        assert_eq!(
            p.key(key(1, Key::Enter, true)).unwrap().command,
            Some(Command::Launch)
        );
        let adopted = p.root(RootEvent::AppRestored { epoch: 7 }).unwrap();
        assert_eq!(adopted.render.unwrap().screen, Screen::AppRunning);
        assert_eq!(
            p.root(RootEvent::AppRestored { epoch: 7 }),
            Err(Error::State)
        );
        assert_eq!(p.root(RootEvent::LaunchRefused), Err(Error::Stale));
        assert_eq!(
            p.key(key(2, Key::Enter, true)).unwrap().command,
            Some(Command::Forward(key(2, Key::Enter, true)))
        );
        p.root(RootEvent::AppStopped { epoch: 7 }).unwrap();
        assert_eq!(
            p.key(key(3, Key::Enter, true)).unwrap().command,
            Some(Command::Launch)
        );
    }
    fn running() -> Policy {
        let mut p = Policy::new();
        p.initial().unwrap();
        assert_eq!(
            p.key(key(1, Key::Enter, false)).unwrap().command,
            Some(Command::Launch)
        );
        p.root(RootEvent::AppStarted { epoch: 257 }).unwrap();
        p
    }
    #[test]
    fn owner_consent_replaces_unsubmitted_picker_with_distinct_pending_state() {
        let mut p = running();
        p.root(RootEvent::PickFile {
            request: 4,
            app_epoch: 257,
        })
        .unwrap();
        let effects = p
            .root(RootEvent::OwnerFilePending {
                request: 4,
                app_epoch: 257,
            })
            .unwrap();
        assert_eq!(effects.render.unwrap().screen, Screen::AppRunning);
        assert!(p.picker.is_none());
        assert_eq!(p.key(key(2, Key::Enter, true)).unwrap().command, None);
        assert_eq!(
            p.root(RootEvent::FileDelivered {
                request: 4,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        assert_eq!(
            p.root(RootEvent::ManagedFileDelivered {
                request: 4,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        assert_eq!(
            p.root(RootEvent::OwnerFileDelivered {
                request: 4,
                app_epoch: 258
            }),
            Err(Error::Stale)
        );
        p.root(RootEvent::OwnerFileDelivered {
            request: 4,
            app_epoch: 257,
        })
        .unwrap();
        assert!(matches!(
            p.key(key(3, Key::Enter, true)).unwrap().command,
            Some(Command::Forward(_))
        ));
        assert_eq!(
            p.root(RootEvent::OwnerFileDelivered {
                request: 4,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
    }
    #[test]
    fn remembered_delivery_requires_exact_managed_request_and_stops_cancel_it() {
        let mut p = running();
        p.root(RootEvent::ManagedFilePending {
            request: 2,
            app_epoch: 257,
        })
        .unwrap();
        assert!(p.picker.is_none());
        assert_eq!(p.key(key(2, Key::Enter, true)).unwrap().command, None);
        assert_eq!(
            p.root(RootEvent::PickFile {
                request: 3,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        assert_eq!(
            p.root(RootEvent::FileDelivered {
                request: 2,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        assert_eq!(
            p.root(RootEvent::OwnerFileDelivered {
                request: 2,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        p.root(RootEvent::ManagedFileDelivered {
            request: 2,
            app_epoch: 257,
        })
        .unwrap();
        assert_eq!(
            p.root(RootEvent::ManagedFilePending {
                request: 2,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        p.root(RootEvent::ManagedFilePending {
            request: 3,
            app_epoch: 257,
        })
        .unwrap();
        p.root(RootEvent::AppStopped { epoch: 257 }).unwrap();
        assert!(p.managed.is_none());
        assert_eq!(
            p.root(RootEvent::ManagedFileDelivered {
                request: 3,
                app_epoch: 257
            }),
            Err(Error::Stale)
        );
        p.root(RootEvent::AppRestored { epoch: 258 }).unwrap();
        p.root(RootEvent::ManagedFilePending {
            request: 4,
            app_epoch: 258,
        })
        .unwrap();
        p.root(RootEvent::InputRestarted).unwrap();
        assert!(p.managed.is_none());
        assert_eq!(
            p.root(RootEvent::ManagedFileDelivered {
                request: 4,
                app_epoch: 258
            }),
            Err(Error::Stale)
        );
    }
    #[test]
    fn shell_replacement_can_restore_actual_app_but_cannot_restore_old_approval() {
        let mut fresh = Policy::new();
        fresh.initial().unwrap();
        let effects = fresh.root(RootEvent::AppRestored { epoch: 257 }).unwrap();
        assert_eq!(effects.render.unwrap().screen, Screen::AppRunning);
        assert!(
            fresh
                .root(RootEvent::FileDelivered {
                    request: 1,
                    app_epoch: 257
                })
                .is_err()
        );
        assert!(fresh.root(RootEvent::AppRestored { epoch: 258 }).is_err());
        let effects = fresh
            .root(RootEvent::PickFile {
                request: 2,
                app_epoch: 257,
            })
            .unwrap();
        assert_eq!(fresh.key(key(1, Key::Enter, true)).unwrap().command, None);
        let frame = effects.render.unwrap().frame;
        arm(&mut fresh, frame, 1);
        assert!(matches!(
            fresh.key(key(2, Key::Enter, true)).unwrap().command,
            Some(Command::Select { request: 2, .. })
        ));
    }
    #[test]
    fn actual_restart_barrier_floor_discards_old_keys_without_forwarding_them() {
        let mut p = running();
        p.root(RootEvent::InputRestarted).unwrap();
        p.input_drained(BarrierReply {
            sequence: 10,
            enter: EnterState::default(),
        })
        .unwrap();
        assert_eq!(p.key(key(9, Key::Enter, true)), Err(Error::Stale));
        assert_eq!(p.key(key(10, Key::Tab, false)), Err(Error::Stale));
        assert_eq!(
            p.key(key(11, Key::Tab, false)).unwrap().command,
            Some(Command::Forward(key(11, Key::Tab, false)))
        );
    }
    fn picker() -> (Policy, u32) {
        let mut p = running();
        let effect = p
            .root(RootEvent::PickFile {
                request: 1,
                app_epoch: 257,
            })
            .unwrap();
        (p, effect.render.unwrap().frame)
    }
    fn arm(p: &mut Policy, frame: u32, sequence: u32) {
        assert_eq!(p.displayed(frame).unwrap().barrier_after_frame, Some(frame));
        p.barrier(
            frame,
            BarrierReply {
                sequence,
                enter: EnterState::default(),
            },
        )
        .unwrap();
    }
    #[test]
    fn stale_held_and_predisplay_keys_never_select_a_file() {
        let (mut p, frame) = picker();
        assert_eq!(p.key(key(2, Key::Enter, true)).unwrap().command, None);
        assert!(
            p.barrier(
                frame,
                BarrierReply {
                    sequence: 2,
                    enter: EnterState::default()
                }
            )
            .is_err()
        );
        arm(&mut p, frame, 5);
        assert_eq!(p.key(key(3, Key::Enter, true)).unwrap().command, None);
        assert_eq!(p.key(key(6, Key::Enter, false)).unwrap().command, None);
        assert_eq!(
            p.key(key(7, Key::Enter, true)).unwrap().command,
            Some(Command::Select {
                request: 1,
                app_epoch: 257,
                file: FileChoice::Notes
            })
        );
        assert_eq!(p.key(key(8, Key::Enter, true)).unwrap().command, None);
    }
    #[test]
    fn changing_choice_requires_new_display_and_barrier() {
        let (mut p, frame) = picker();
        arm(&mut p, frame, 2);
        let changed = p.key(key(3, Key::Down, false)).unwrap().render.unwrap();
        assert_eq!(
            changed.screen,
            Screen::Picker {
                selected: FileChoice::Private
            }
        );
        assert_eq!(p.key(key(4, Key::Enter, true)).unwrap().command, None);
        assert!(p.displayed(frame).is_err());
        arm(&mut p, changed.frame, 4);
        assert_eq!(
            p.key(key(5, Key::Enter, true)).unwrap().command,
            Some(Command::Select {
                request: 1,
                app_epoch: 257,
                file: FileChoice::Private
            })
        );
    }
    #[test]
    fn submission_redraw_acknowledges_without_rearming_or_selecting_again() {
        let (mut p, picker_frame) = picker();
        arm(&mut p, picker_frame, 2);
        let approval = p.key(key(3, Key::Enter, true)).unwrap();
        assert_eq!(
            approval.command,
            Some(Command::Select {
                request: 1,
                app_epoch: 257,
                file: FileChoice::Notes,
            })
        );
        let opening = approval.render.unwrap();
        assert_eq!(
            opening.screen,
            Screen::Opening {
                selected: FileChoice::Notes,
            }
        );
        assert_eq!(p.displayed(opening.frame), Ok(Effects::default()));
        assert_eq!(p.displayed(picker_frame), Err(Error::Stale));
        assert_eq!(
            p.barrier(
                opening.frame,
                BarrierReply {
                    sequence: 3,
                    enter: EnterState::default(),
                },
            ),
            Err(Error::Stale)
        );
        for event in [
            key(4, Key::Enter, true),
            key(5, Key::Enter, false),
            key(6, Key::Enter, true),
        ] {
            assert_eq!(p.key(event), Ok(Effects::default()));
        }
        let delivered = p
            .root(RootEvent::FileDelivered {
                request: 1,
                app_epoch: 257,
            })
            .unwrap()
            .render
            .unwrap();
        assert_eq!(delivered.screen, Screen::AppRunning);
        assert_eq!(p.displayed(delivered.frame), Ok(Effects::default()));
    }
    #[test]
    fn app_or_input_replacement_cancels_the_exact_pending_request() {
        for input in [false, true] {
            let (mut p, frame) = picker();
            arm(&mut p, frame, 2);
            let event = if input {
                RootEvent::InputRestarted
            } else {
                RootEvent::AppStopped { epoch: 257 }
            };
            assert_eq!(
                p.root(event).unwrap().command,
                Some(Command::Cancel { request: 1 })
            );
            assert!(
                p.barrier(
                    frame,
                    BarrierReply {
                        sequence: 3,
                        enter: EnterState::default()
                    }
                )
                .is_err()
            );
            assert!(!matches!(
                p.key(key(4, Key::Enter, true)).unwrap().command,
                Some(Command::Select { .. })
            ));
        }
    }
    #[test]
    fn an_old_app_or_request_cannot_be_substituted() {
        let (mut p, _) = picker();
        assert!(p.root(RootEvent::AppStopped { epoch: 258 }).is_err());
        assert!(
            p.root(RootEvent::PickFile {
                request: 2,
                app_epoch: 258
            })
            .is_err()
        );
        p.root(RootEvent::AppStopped { epoch: 257 }).unwrap();
        p.key(key(2, Key::Enter, false)).unwrap();
        p.root(RootEvent::AppStarted { epoch: 513 }).unwrap();
        assert!(
            p.root(RootEvent::PickFile {
                request: 1,
                app_epoch: 513
            })
            .is_err()
        );
        assert!(
            p.root(RootEvent::FileDelivered {
                request: 1,
                app_epoch: 257
            })
            .is_err()
        );
    }
    #[test]
    fn key_and_visual_counters_refuse_replay_or_wrap() {
        let mut p = running();
        assert!(p.key(key(1, Key::Tab, false)).is_err());
        assert!(p.key(key(u32::MAX, Key::Enter, true)).is_err());
        p.frame = u32::MAX - 1;
        assert_eq!(p.key(key(2, Key::Escape, false)), Err(Error::Counter));
        assert_eq!(p.screen(), Screen::AppRunning);
    }
}
