//! Bounded actual mechanism diagnostics; no policy or reply synthesis.
use crate::provider_runtime::{ActorKind, LifeKind, Observation, Proof};
use core::fmt::Write;
fn digest(serial: &mut impl Write, bytes: [u8; 32]) {
    for byte in bytes {
        write!(serial, "{byte:02x}").expect("provider actual digest");
    }
}
fn body(serial: &mut impl Write, value: u64) {
    for byte in value.to_le_bytes() {
        write!(serial, "{byte:02x}").expect("provider opaque body");
    }
}
#[inline(never)]
pub fn observation(serial: &mut impl Write, build: &str, observation: Observation) {
    match observation {
        Observation::Measurement { root, event } => {
            let _ = (root, event);
            panic!("measurement cannot enter provider serializer")
        }
        Observation::Lifecycle(event) => {
            let actor = match event.actor {
                ActorKind::Root => "root",
                ActorKind::Consumer => "consumer",
                ActorKind::Provider => "provider",
            };
            let kind = match event.kind {
                LifeKind::Start => "start",
                LifeKind::Stop => "stop",
                LifeKind::Reap => "reap",
                LifeKind::Exit => "exit",
            };
            write!(serial,"EVROSION_M5_PROVIDER_LIFECYCLE protocol=1 build={build} actor={actor} event={kind} process={} thread={} exit_code=",event.identity.process,event.identity.thread).expect("provider actual lifecycle");
            if let Some(code) = event.exit_code {
                write!(serial, "{code}").expect("provider actual exit");
            } else {
                write!(serial, "none").expect("provider nonexit lifecycle");
            }
            write!(serial, " image_sha256=").expect("provider lifecycle digest key");
            digest(serial, event.identity.image_sha256);
            writeln!(serial).expect("provider lifecycle complete");
        }
        Observation::Binding(event) => {
            write!(serial,"EVROSION_M5_PROVIDER_BIND protocol=1 build={build} owner_process={} owner_thread={} endpoint={} process={} thread={} image_sha256=",event.owner.process,event.owner.thread,event.endpoint,event.target.process,event.target.thread).expect("provider actual receiver binding");
            digest(serial, event.target.image_sha256);
            writeln!(serial).expect("provider binding complete");
        }
        Observation::Call(event) => {
            write!(serial,"EVROSION_M5_PROVIDER_CALL protocol=1 build={build} nonce={} endpoint={} send_handle={} caller_process={} caller_thread={} caller_image_sha256=",event.nonce,event.endpoint,event.send_handle,event.caller.process,event.caller.thread).expect("provider actual call");
            digest(serial, event.caller.image_sha256);
            write!(
                serial,
                " callee_process={} callee_thread={} callee_image_sha256=",
                event.callee.process, event.callee.thread
            )
            .expect("provider actual callee");
            digest(serial, event.callee.image_sha256);
            write!(serial, " request=").expect("provider request key");
            body(serial, event.request);
            write!(serial, " reply=").expect("provider reply key");
            body(serial, event.reply);
            writeln!(serial).expect("provider call complete");
        }
    }
}
pub fn footer(serial: &mut impl Write, build: &str, proof: Proof) {
    writeln!(serial,"EVROSION_M5_PROVIDER protocol=1 build={build} status=PASS actors={} starts={} stops={} reaps={} exits={} calls={} replies={} bindings={} root_exit={} consumer_exit={} outer_ready={} switch_complete={} frames={} metadata={} mappings={} authority={}",proof.actors,proof.starts,proof.stops,proof.reaps,proof.exits,proof.calls,proof.replies,proof.bindings,proof.root_exit.expect("actual Root Exit required"),proof.consumer_exit.expect("actual consumer Exit required"),proof.outer_ready,proof.switch_complete,proof.frames,proof.metadata,proof.mappings,proof.authority).expect("provider complete resource proof");
}
