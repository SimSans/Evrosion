//! UART only at owned lifecycle and aggregate batch boundaries, never per RPC.
use crate::provider_runtime::{Identity, LifeKind, Lifecycle, Observation, Proof, measurement};
use core::fmt::{self, Write};
fn hex(out: &mut impl Write, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(out, "{b:02x}")?;
    }
    Ok(())
}
fn identity(out: &mut impl Write, name: &str, id: Identity) -> fmt::Result {
    write!(
        out,
        " {name}_process={} {name}_thread={} {name}_image_sha256=",
        id.process, id.thread
    )?;
    hex(out, &id.image_sha256)
}
#[inline(never)] // Auditable concrete callback symbol for linked stack census.
pub fn observation(out: &mut impl Write, build: &str, event: Observation) {
    match event {
        Observation::Lifecycle(Lifecycle {
            actor,
            kind,
            identity: id,
            exit_code,
        }) => {
            let actor = match actor {
                crate::provider_runtime::ActorKind::Root => "root",
                crate::provider_runtime::ActorKind::Consumer => "client",
                crate::provider_runtime::ActorKind::Provider => "server",
            };
            let kind = match kind {
                LifeKind::Start => "start",
                LifeKind::Stop => "stop",
                LifeKind::Reap => "reap",
                LifeKind::Exit => "exit",
            };
            write!(
                out,
                "EVROSION_M5_IPC_LIFECYCLE protocol=1 build={build} actor={actor} event={kind}"
            )
            .unwrap();
            identity(out, "actor", id).unwrap();
            writeln!(
                out,
                " exit_code={}",
                exit_code.map_or("none", |code| if code == 0 { "0" } else { "nonzero" })
            )
            .unwrap();
        }
        Observation::Binding(b) => {
            write!(
                out,
                "EVROSION_M5_IPC_BINDING protocol=1 build={build} endpoint={}",
                b.endpoint
            )
            .unwrap();
            identity(out, "root", b.owner).unwrap();
            identity(out, "server", b.target).unwrap();
            writeln!(out).unwrap();
        }
        Observation::Call(c) => {
            let _opaque_payload = (c.request, c.reply);
            panic!("per-call UART must not enter benchmark adapter")
        }
        Observation::Measurement { root, event } => match event {
            measurement::Event::Ready => {
                write!(out, "EVROSION_M5_IPC_READY protocol=1 build={build}").unwrap();
                identity(out, "root", root).unwrap();
                writeln!(out).unwrap();
            }
            measurement::Event::Snapshot(s) => {
                let route = s
                    .route
                    .expect("actual batch must have observed a completed route");
                write!(out,"EVROSION_M5_IPC_BATCH protocol=1 build={build} phase={} tick={} calls={} replies={} rejected={} completed={} first_nonce={} last_nonce={} endpoint={} send_handle={}",if s.phase==1{"before"}else{"after"},s.tick,s.calls,s.replies,s.rejected,s.completed,s.first_nonce,s.last_nonce,route.endpoint,route.send_handle).unwrap();
                identity(out, "root", root).unwrap();
                identity(out, "client", route.caller).unwrap();
                identity(out, "server", route.callee).unwrap();
                writeln!(out).unwrap();
            }
            measurement::Event::Sample(words) => {
                write!(out,"EVROSION_M5_IPC_SAMPLE protocol=1 build={build} warmups={} rounds={} first_tick={} last_tick={}",words[0],words[1],words[2],words[3]).unwrap();
                identity(out, "root", root).unwrap();
                writeln!(out).unwrap();
            }
            measurement::Event::Finish => {
                write!(out, "EVROSION_M5_IPC_FINISH protocol=1 build={build}").unwrap();
                identity(out, "root", root).unwrap();
                writeln!(out).unwrap();
            }
        },
    }
}
pub fn footer(out: &mut impl Write, build: &str, p: Proof) {
    writeln!(out,"EVROSION_M5_IPC protocol=1 build={build} status=PASS actors={} starts={} stops={} reaps={} exits={} calls={} replies={} rejected={} bindings={} root_exit={} client_exit={} outer_ready={} batch_finished={} switch_complete={} frames={} metadata={} mappings={} authority={}",p.actors,p.starts,p.stops,p.reaps,p.exits,p.calls,p.replies,p.rejected_calls,p.bindings,p.root_exit.expect("actual Root exit"),p.consumer_exit.expect("actual client exit"),p.outer_ready,p.batch_finished,p.switch_complete,p.frames,p.metadata,p.mappings,p.authority).unwrap();
}
