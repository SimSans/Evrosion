//! Root-owned transient presentation scope, never serialized as capabilities.
//! The actual adapter must first authenticate its current live Shell endpoint.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct App {
    pub process: u64,
    pub thread: u64,
    pub epoch: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Next {
    pub generation: u64,
    pub manifest: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub shell_process: u64,
    pub shell_thread: u64,
    pub shell_epoch: u32,
    pub input_epoch: u32,
    pub modal: u32,
    /// Current actual Registry head; zero denotes the verified new namespace.
    pub registry_revision: u64,
    pub app: Option<App>,
    pub candidate: Option<[u8; 32]>,
    /// Actual durable selected-next System reference, never a staged App label.
    pub next: Option<Next>,
    /// Actual backend/clock/client/image ownership fence.
    pub unavailable: bool,
    /// Verified setup prerequisite; a cached hint grants no selection authority.
    pub setup_required: bool,
}
impl Context {
    fn valid(self) -> bool {
        self.shell_process != 0
            && self.shell_process != u64::MAX
            && self.shell_thread != 0
            && self.shell_thread != u64::MAX
            && self.shell_epoch != 0
            && self.shell_epoch != u32::MAX
            && self.input_epoch != 0
            && self.input_epoch != u32::MAX
            && self.registry_revision != u64::MAX
            && self.app.is_none_or(|a| {
                a.process != 0
                    && a.process != u64::MAX
                    && a.thread != 0
                    && a.thread != u64::MAX
                    && a.epoch != 0
                    && a.epoch != u32::MAX
                    && a.process != self.shell_process
            })
            && self.candidate.is_none_or(|p| p != [0; 32])
            && self.next.is_none_or(|n| {
                n.generation != 0 && n.generation != u64::MAX && n.manifest != [0; 32]
            })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Fetch,
    SelectNext,
    Restart,
    ConfirmRestart,
    Leave,
}
pub struct Gate {
    next: u32,
    presented: Option<(Presentation, Context)>,
    settled: bool,
    consumed: bool,
}
impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}
impl Gate {
    pub const fn new() -> Self {
        Self {
            next: 0,
            presented: None,
            settled: false,
            consumed: false,
        }
    }
    pub fn present(&mut self, status: Status, actual: Context) -> Result<Presentation, Error> {
        if !actual.valid()
            || status.app_running != actual.app.is_some()
            || status.candidate_available != actual.candidate.is_some()
            || (actual.unavailable != matches!(status.update, Update::Unavailable))
            || (actual.setup_required != matches!(status.update, Update::SetupRequired))
            || (matches!(status.update, Update::Selected) && actual.next.is_none())
        {
            return Err(Error::State);
        }
        let revision = self
            .next
            .checked_add(1)
            .filter(|n| *n < 0x007f_ffff)
            .ok_or(Error::Counter)?;
        let p = Presentation { revision, status };
        p.word()?;
        self.next = revision;
        self.presented = Some((p, actual));
        self.settled = false;
        self.consumed = false;
        Ok(p)
    }
    /// Call only for the actual authenticated matching ControlSettled reply.
    pub fn settled(&mut self, word: u32, actual: Context) -> Result<(), Error> {
        let Some((p, context)) = self.presented else {
            return Err(Error::State);
        };
        if p.word()? != word || context != actual || self.settled || self.consumed {
            return Err(Error::Stale);
        }
        self.settled = true;
        Ok(())
    }
    /// `actual` must be freshly derived from the real current Root state, not
    /// IDs or hashes supplied by the request. Accepted output starts no IO here.
    pub fn request(&mut self, request: Request, actual: Context) -> Result<Outcome, Error> {
        request.encode()?;
        let Some((p, context)) = self.presented else {
            return Err(Error::State);
        };
        if !self.settled || self.consumed || request.revision != p.revision || context != actual {
            return Err(Error::Stale);
        }
        let action = match request.operation {
            Operation::Fetch => Action::Fetch,
            Operation::SelectNext => Action::SelectNext,
            Operation::Restart => Action::Restart,
            Operation::Confirm => Action::Confirm,
            Operation::Cancel => Action::Cancel,
            Operation::Back => Action::Back,
            Operation::Open => return Err(Error::State),
        };
        if !connection::enabled(p.status, action) {
            return Err(Error::State);
        }
        let outcome = match request.operation {
            Operation::Fetch => Outcome::Fetch,
            Operation::SelectNext => Outcome::SelectNext,
            Operation::Restart => Outcome::ConfirmRestart,
            Operation::Confirm => Outcome::Restart,
            Operation::Cancel | Operation::Back => Outcome::Leave,
            _ => return Err(Error::State),
        };
        self.consumed = true;
        self.settled = false;
        Ok(outcome)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Context {
        Context {
            shell_process: 2,
            shell_thread: 12,
            shell_epoch: 1,
            input_epoch: 1,
            modal: 0,
            registry_revision: 1,
            app: Some(App {
                process: 3,
                thread: 13,
                epoch: 1,
            }),
            candidate: Some([4; 32]),
            next: None,
            unavailable: false,
            setup_required: false,
        }
    }
    fn ready() -> Status {
        Status {
            connection: Connection::Online,
            update: Update::Ready,
            app_running: true,
            confirm: false,
            candidate_available: true,
        }
    }
    #[test]
    fn displayed_labels_and_unsettled_or_stale_context_never_start_an_update() {
        let mut g = Gate::new();
        let p = g.present(ready(), context()).unwrap();
        let r = Request {
            operation: Operation::SelectNext,
            revision: p.revision,
        };
        assert!(g.request(r, context()).is_err());
        g.settled(p.word().unwrap(), context()).unwrap();
        for other in [
            Context {
                registry_revision: 2,
                ..context()
            },
            Context {
                candidate: Some([5; 32]),
                ..context()
            },
            Context {
                input_epoch: 2,
                ..context()
            },
            Context {
                modal: 5,
                ..context()
            },
            Context {
                shell_epoch: 2,
                ..context()
            },
            Context {
                app: Some(App {
                    process: 7,
                    ..context().app.unwrap()
                }),
                ..context()
            },
        ] {
            assert!(g.request(r, other).is_err());
        }
        assert_eq!(g.request(r, context()), Ok(Outcome::SelectNext));
        assert!(g.request(r, context()).is_err());
    }
    #[test]
    fn selecting_next_keeps_the_live_app_and_restart_requires_another_fresh_confirmation() {
        let mut g = Gate::new();
        let original = context();
        let p = g.present(ready(), original).unwrap();
        g.settled(p.word().unwrap(), original).unwrap();
        assert_eq!(
            g.request(
                Request {
                    operation: Operation::SelectNext,
                    revision: p.revision
                },
                original
            ),
            Ok(Outcome::SelectNext)
        );
        // Only the actual System Store ACK supplies a new selected reference.
        let selected = Context {
            next: Some(Next {
                generation: 2,
                manifest: [8; 32],
            }),
            ..original
        };
        let selected_status = Status {
            update: Update::Selected,
            ..ready()
        };
        let p = g.present(selected_status, selected).unwrap();
        g.settled(p.word().unwrap(), selected).unwrap();
        assert_eq!(
            g.request(
                Request {
                    operation: Operation::Restart,
                    revision: p.revision
                },
                selected
            ),
            Ok(Outcome::ConfirmRestart)
        );
        let confirm = g
            .present(
                Status {
                    confirm: true,
                    ..selected_status
                },
                selected,
            )
            .unwrap();
        assert!(
            g.request(
                Request {
                    operation: Operation::Confirm,
                    revision: confirm.revision
                },
                selected
            )
            .is_err()
        );
        g.settled(confirm.word().unwrap(), selected).unwrap();
        assert!(
            g.request(
                Request {
                    operation: Operation::Confirm,
                    revision: p.revision
                },
                selected
            )
            .is_err()
        );
        assert!(
            g.request(
                Request {
                    operation: Operation::Confirm,
                    revision: confirm.revision
                },
                Context {
                    next: Some(Next {
                        generation: 3,
                        manifest: [9; 32]
                    }),
                    ..selected
                }
            )
            .is_err()
        );
        assert_eq!(
            g.request(
                Request {
                    operation: Operation::Confirm,
                    revision: confirm.revision
                },
                selected
            ),
            Ok(Outcome::Restart)
        );
        assert_eq!(selected.app, original.app);
    }
    #[test]
    fn cancel_keeps_actual_app_and_candidate_and_never_activates() {
        let mut g = Gate::new();
        let original = Context {
            next: Some(Next {
                generation: 2,
                manifest: [8; 32],
            }),
            ..context()
        };
        let p = g
            .present(
                Status {
                    confirm: true,
                    update: Update::Selected,
                    ..ready()
                },
                original,
            )
            .unwrap();
        g.settled(p.word().unwrap(), original).unwrap();
        assert_eq!(
            g.request(
                Request {
                    operation: Operation::Cancel,
                    revision: p.revision
                },
                original
            ),
            Ok(Outcome::Leave)
        );
        assert!(
            g.request(
                Request {
                    operation: Operation::Confirm,
                    revision: p.revision
                },
                original
            )
            .is_err()
        );
        assert_eq!(context().app, original.app);
    }
    #[test]
    fn an_actual_ownership_fence_cannot_be_rendered_as_retryable_or_bypassed() {
        let mut g = Gate::new();
        let fenced = Context {
            unavailable: true,
            ..context()
        };
        assert!(
            g.present(
                Status {
                    update: Update::Failed,
                    ..ready()
                },
                fenced
            )
            .is_err()
        );
        let p = g
            .present(
                Status {
                    update: Update::Unavailable,
                    ..ready()
                },
                fenced,
            )
            .unwrap();
        g.settled(p.word().unwrap(), fenced).unwrap();
        for operation in [
            Operation::Fetch,
            Operation::SelectNext,
            Operation::Restart,
            Operation::Confirm,
        ] {
            assert!(
                g.request(
                    Request {
                        operation,
                        revision: p.revision
                    },
                    fenced
                )
                .is_err()
            );
        }
        assert_eq!(
            g.request(
                Request {
                    operation: Operation::Back,
                    revision: p.revision
                },
                fenced
            ),
            Ok(Outcome::Leave)
        );
        assert!(
            g.present(
                Status {
                    update: Update::Selected,
                    ..ready()
                },
                context()
            )
            .is_err()
        );
    }
    #[test]
    fn setup_change_invalidates_old_approval_and_new_preparation_needs_fresh_settlement() {
        let mut g = Gate::new();
        let current = context();
        let p = g.present(ready(), current).unwrap();
        g.settled(p.word().unwrap(), current).unwrap();
        let needed = Context {
            setup_required: true,
            ..current
        };
        assert!(
            g.request(
                Request {
                    operation: Operation::SelectNext,
                    revision: p.revision
                },
                needed
            )
            .is_err()
        );
        let status = Status {
            update: Update::SetupRequired,
            ..ready()
        };
        assert!(g.present(status, current).is_err());
        assert!(g.present(ready(), needed).is_err());
        let setup = g.present(status, needed).unwrap();
        g.settled(setup.word().unwrap(), needed).unwrap();
        for operation in [Operation::Fetch, Operation::Restart, Operation::Confirm] {
            assert!(
                g.request(
                    Request {
                        operation,
                        revision: setup.revision
                    },
                    needed
                )
                .is_err()
            );
        }
        assert!(
            g.request(
                Request {
                    operation: Operation::SelectNext,
                    revision: setup.revision
                },
                current
            )
            .is_err()
        );
        assert_eq!(
            g.request(
                Request {
                    operation: Operation::SelectNext,
                    revision: setup.revision
                },
                needed
            ),
            Ok(Outcome::SelectNext)
        );
        assert!(
            g.request(
                Request {
                    operation: Operation::SelectNext,
                    revision: setup.revision
                },
                needed
            )
            .is_err()
        );
        let fresh = g.present(ready(), current).unwrap();
        assert!(
            g.request(
                Request {
                    operation: Operation::SelectNext,
                    revision: fresh.revision
                },
                current
            )
            .is_err()
        );
        g.settled(fresh.word().unwrap(), current).unwrap();
        assert_eq!(
            g.request(
                Request {
                    operation: Operation::SelectNext,
                    revision: fresh.revision
                },
                current
            ),
            Ok(Outcome::SelectNext)
        );
    }
}
