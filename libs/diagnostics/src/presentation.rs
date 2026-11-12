//! Readable views of explicit diagnostic records; never collection or authority.
use crate::live::hex;
use crate::{Component, Crash};
use core::fmt::{self, Write};
fn optional(out: &mut impl Write, value: Option<[u8; 32]>) -> fmt::Result {
    if let Some(value) = value {
        hex(out, &value)
    } else {
        write!(out, "none")
    }
}
pub fn crash(out: &mut impl Write, crash: &Crash) -> fmt::Result {
    let p = crash.provenance();
    let c = crash.capture();
    write!(out, "Evrosion captured crash | ")?;
    match p.component {
        Component::Application(id) => {
            write!(out, "AppId ")?;
            hex(out, &id.bytes())?;
        }
        Component::Service(role) => write!(out, "service role {role}")?,
    }
    writeln!(
        out,
        " | epoch={} Root-incarnation={} | Job={} process={} thread={}",
        p.epoch, p.incarnation, c.job, c.process, c.thread
    )?;
    write!(out, "  executable SHA256 ")?;
    hex(out, &p.image)?;
    write!(out, "\n  component build identity ")?;
    hex(out, &p.component_build)?;
    write!(out, "\n  package ")?;
    optional(out, p.package)?;
    write!(out, "\n  actual System generation ")?;
    if p.generation.is_none() {
        writeln!(
            out,
            "unknown: this Native boot has no matched durable System admission"
        )?;
    } else {
        optional(out, p.generation)?;
        writeln!(out)?;
    }
    writeln!(
        out,
        "  vector={} error={} address={:#x} RIP={:#x} RSP={:#x} RFLAGS={:#x}",
        c.vector, c.error, c.address, c.instruction, c.stack, c.flags
    )?;
    for (name, value) in crate::REGISTERS.into_iter().zip(c.registers) {
        writeln!(out, "  {name}={value:#018x}")?;
    }
    Ok(())
}
