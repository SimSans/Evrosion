//! Source collection under actual retained Process/Job controls. Every report
//! uses the ordinary bounded Events mailbox; partial output never completes.
use super::*;
use ev_diagnostics::{
    framing::{CrashArchive, Kind, Outbox},
    live::{Role as JobRole, Row},
};
use ev_root_supervisor::native_diagnostics::{
    self as collect, Collector, JobAuthority, StoppedTarget, Syscalls,
};

pub(super) struct Diagnostics {
    outbox: Outbox,
    archive: CrashArchive,
    serial: u32,
    completed: u32,
    pub(super) inspect_next: Option<u8>,
}
impl Diagnostics {
    pub(super) const fn new() -> Self {
        Self {
            outbox: Outbox::new(),
            archive: CrashArchive::new(),
            serial: 0,
            completed: 0,
            inspect_next: None,
        }
    }
    fn queue(&mut self, kind: Kind, bytes: &[u8]) -> u32 {
        self.serial = self.serial.checked_add(1).unwrap_or_else(|| fail(970));
        self.outbox
            .start(kind, self.serial, bytes)
            .unwrap_or_else(|_| fail(971));
        self.serial
    }
}
fn role(child: Child) -> JobRole {
    match child {
        Child::Shell => JobRole::Shell,
        Child::Input => JobRole::Input,
        Child::File => JobRole::File,
        Child::Block => JobRole::Block,
        Child::App => JobRole::Application,
        Child::Display => JobRole::Display,
    }
}
impl Root<'_> {
    pub(in crate::desktop) fn native_diagnostic_stopped(&mut self, child: Child) -> bool {
        let n = self.native.as_mut().unwrap();
        if child == Child::App {
            n.state.fence();
        }
        // Kernel retains the stopped image/context until the previous report
        // is accepted. Return to ordinary receive/tick instead of recursive wait.
        if n.diagnostics.outbox.pending() {
            return false;
        }
        let old = self.child(child);
        let context = self.bootstrap.context();
        let mut provenance = if child == Child::App {
            let n = self.native.as_ref().unwrap();
            let slot = n.running.unwrap_or_else(|| fail(972));
            collect::application_provenance(
                n.packages.checked(slot).unwrap_or_else(|_| fail(973)),
                context.epoch,
                context.incarnation,
            )
        } else {
            collect::service_provenance(
                child,
                self.native_system_image_digest(child)
                    .unwrap_or_else(|| self.catalogue.images().nth(child.index()).unwrap().image),
                self.catalogue.kernel_input(),
                context.epoch,
                context.incarnation,
            )
            .unwrap_or_else(|_| fail(974))
        };
        provenance.generation = self.native_system_provenance();
        let target = StoppedTarget {
            process_control: old.control,
            job_control: old.job,
            identity: collect::Identity {
                process: old.identity.process,
                thread: old.identity.thread,
            },
        };
        if let Some(captured) = Collector::new(Syscalls)
            .fault(&target, provenance)
            .unwrap_or_else(|_| fail(975))
        {
            let d = &mut self.native.as_mut().unwrap().diagnostics;
            let slot = d.archive.push(captured.crash).unwrap_or_else(|_| fail(976));
            // Archive retains both bounded App+Shell capsules. The outbox owns
            // an independent byte copy before the physical child can be reaped.
            d.serial = d.serial.checked_add(1).unwrap_or_else(|| fail(970));
            d.outbox
                .start(Kind::Crash, d.serial, d.archive.payload(slot).unwrap())
                .unwrap_or_else(|_| fail(971));
        }
        true
    }
    pub(super) fn native_diagnostic_tick(&mut self) -> bool {
        let events = self.bootstrap.handle(Role::Events);
        let d = &mut self.native.as_mut().unwrap().diagnostics;
        if d.outbox.pending() {
            if collect::tick(&mut d.outbox, &mut Syscalls, events).unwrap_or_else(|_| fail(977))
                == collect::Progress::Finished
            {
                d.completed = d.serial;
            }
            return true;
        }
        let Some(index) = d.inspect_next else {
            return false;
        };
        d.inspect_next = Some(index + 1);
        if index < 8 {
            self.native_job_row(index);
        } else if index == 8 {
            self.native_queue_system_snapshot();
        } else {
            self.native.as_mut().unwrap().diagnostics.inspect_next = None;
            // This completion is ordered after every requested actual Job row
            // and read-only System result has been accepted in full.
            self.native_report("inspect", "ok");
        }
        true
    }
    pub(super) fn native_queue_system_snapshot(&mut self) {
        let first = now();
        let deadline = self.deadline();
        let state = self.native.as_mut().unwrap().state.inspect_system(deadline);
        let mut snapshot = state.snapshot(first, now());
        snapshot.current = self.native_system_snapshot();
        self.native.as_mut().unwrap().diagnostics.queue(
            Kind::System,
            &snapshot.encode().unwrap_or_else(|_| fail(978)),
        );
    }
    pub(super) fn native_owner_report(&mut self, prompt: ev_diagnostics::owner::Prompt) -> u32 {
        self.native.as_mut().unwrap().diagnostics.queue(
            Kind::OwnerPrompt,
            &prompt.encode().unwrap_or_else(|_| fail(986)),
        )
    }
    pub(super) fn native_output_pending(&self) -> bool {
        self.native.as_ref().unwrap().diagnostics.outbox.pending()
    }
    pub(super) fn native_output_completed(&self, serial: u32) -> bool {
        self.native.as_ref().unwrap().diagnostics.completed >= serial
    }
    fn native_job_row(&mut self, index: u8) {
        let (job_role, identity, started, image, package, authority) = if index == 0 {
            // A real installed Memory capability cannot select a Job. This
            // read-only negative neither creates nor attenuates authority.
            let denied = rt::call(
                syscall::JOB_INFO,
                self.bootstrap.handle(Role::Catalogue),
                0,
                0,
            );
            require(
                denied.status == 1 && denied.value == 0 && denied.capability == 0,
                985,
            );
            (
                JobRole::Boot,
                collect::Identity {
                    process: 0,
                    thread: 0,
                },
                false,
                [0; 32],
                None,
                JobAuthority::Delegated(self.bootstrap.handle(Role::CreatorJob)),
            )
        } else if index == 1 {
            let r = rt::call4(syscall::PROCESS_IDENTITY, 0, 0, 0, 0);
            require(
                r.status == 0 && r.value == self.bootstrap.context().process && r.capability != 0,
                979,
            );
            (
                JobRole::Root,
                collect::Identity {
                    process: r.value,
                    thread: r.capability,
                },
                true,
                self.catalogue.root_image(),
                None,
                JobAuthority::Current,
            )
        } else {
            let child = graph::CHILDREN[(index - 2) as usize];
            let Some(actor) = self.actors[child.index()] else {
                return;
            };
            let (image, package) = if child == Child::App {
                let n = self.native.as_ref().unwrap();
                let slot = n.preparing.or(n.running).unwrap_or_else(|| fail(980));
                let p = n.packages.checked(slot).unwrap_or_else(|_| fail(981));
                (p.executable().digest, Some(p.id().bytes()))
            } else {
                (
                    self.native_system_image_digest(child).unwrap_or_else(|| {
                        self.catalogue.images().nth(child.index()).unwrap().image
                    }),
                    None,
                )
            };
            (
                role(child),
                collect::Identity {
                    process: actor.identity.process,
                    thread: actor.identity.thread,
                },
                actor.identity.process != 0,
                image,
                package,
                JobAuthority::Delegated(actor.job),
            )
        };
        let job = Collector::new(Syscalls)
            .job(authority)
            .unwrap_or_else(|_| fail(982));
        let row = Row::new(job_role, identity, started, image, package, job)
            .unwrap_or_else(|_| fail(983));
        self.native
            .as_mut()
            .unwrap()
            .diagnostics
            .queue(Kind::Job, &row.encode());
    }
}
