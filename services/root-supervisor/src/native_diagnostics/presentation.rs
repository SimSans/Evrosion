//! Textual Native inspector assembled from actual collected records.
use super::system::State as SystemState;
use core::fmt::{self, Write};
pub use ev_diagnostics::live::{Error, Identity, Role, Row, hex};
pub struct AppState {
    pub id: [u8; 16],
    pub installed: bool,
    pub active: Option<[u8; 32]>,
    pub staged: Option<[u8; 32]>,
    pub previous: Option<[u8; 32]>,
    pub revision: u64,
}
fn optional(out: &mut impl Write, value: Option<[u8; 32]>) -> fmt::Result {
    if let Some(value) = value {
        hex(out, &value)
    } else {
        write!(out, "none")
    }
}
pub const MAX_ROWS: usize = 16;
pub fn inspector(
    out: &mut impl Write,
    app: &AppState,
    system: &SystemState,
    rows: &[Row],
) -> fmt::Result {
    if rows.len() > MAX_ROWS
        || rows.iter().enumerate().any(|(i, row)| {
            rows[..i]
                .iter()
                .any(|old| old.role == row.role || old.job.diagnostic_id == row.job.diagnostic_id)
        })
    {
        return Err(fmt::Error);
    }
    writeln!(
        out,
        "Evrosion inspector: actual Job observations over stated tick intervals; hierarchical subtree usage, not an atomic machine total or CPU percentage."
    )?;
    write!(out, "Application ")?;
    hex(out, &app.id)?;
    writeln!(
        out,
        " | installed={} | registry revision={}",
        app.installed, app.revision
    )?;
    for (label, value) in [
        ("active package", app.active),
        ("staged package", app.staged),
        ("previous package", app.previous),
    ] {
        write!(out, "  {label}: ")?;
        optional(out, value)?;
        writeln!(out)?;
    }
    system.write(out)?;
    for row in rows {
        row.write(out)?;
    }
    Ok(())
}

pub use ev_diagnostics::presentation::crash;
