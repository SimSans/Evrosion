#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_userspace_runtime as rt;
#[cfg(not(any(
    feature = "display",
    feature = "input",
    feature = "shell",
    feature = "interactive"
)))]
mod app;
#[cfg(feature = "compositor")]
mod compositor;
#[cfg(all(feature = "display", not(feature = "compositor")))]
mod display;
#[cfg(all(feature = "input", not(feature = "display")))]
mod input;
#[cfg(all(
    feature = "interactive",
    not(any(feature = "display", feature = "input", feature = "shell"))
))]
mod interactive;
#[cfg(all(
    feature = "shell",
    not(any(feature = "display", feature = "input", feature = "native-bad-shell"))
))]
mod shell;
#[cfg(all(
    not(feature = "native-bad-shell"),
    any(feature = "display", not(feature = "input"))
))]
mod surface;
#[cfg(all(
    feature = "native-bad-shell",
    any(feature = "display", feature = "input", feature = "interactive")
))]
compile_error!("native-bad-shell is one distinct measured Shell actor");
// SAFETY: one measured freestanding image owns the shared entry/intrinsics.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: the ordinary ELF loader measures, charges and guards this16KiB NX
// private stack; no live mapping or user-supplied stack pointer is accepted.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp, 0x8000104000",
    "and rsp,-16",
    "call ev_desktop_main",
    "ud2"
);
pub(crate) fn require(ok: bool, code: u64) {
    if !ok {
        rt::exit(code);
    }
}
pub(crate) fn now() -> u64 {
    let r = rt::monotonic();
    require(r.status == 0 && r.capability == 0, 700);
    r.value
}
#[cfg(all(
    not(feature = "native-bad-shell"),
    any(feature = "display", not(feature = "input"))
))]
pub(crate) fn yield_now() {
    let r = rt::yield_now();
    require(r.status == 0 && r.value == 0 && r.capability == 0, 701);
}
#[cfg(all(
    not(feature = "native-bad-shell"),
    any(feature = "display", not(feature = "input"))
))]
pub(crate) fn event(cap: u64, bytes: [u8; 8], stop: u64) {
    loop {
        require(now() < stop, 702);
        let r = rt::send(cap, bytes);
        require(r.value == 0 && r.capability == 0, 708);
        match r.status {
            0 => return,
            // Canonical Full is rejected before acceptance; retry the same
            // immutable bytes without dropping, duplicating or inventing Ready.
            2 => yield_now(),
            _ => rt::exit(709),
        }
    }
}
pub(crate) fn grant(
    b: &ev_userspace_contract::Bootstrap<'_>,
    selector: u64,
    kind: u8,
    rights: u16,
) -> u64 {
    let g = b
        .grants()
        .find(|g| g.selector == selector)
        .unwrap_or_else(|| rt::exit(703));
    require(g.kind == kind && g.rights == rights, 704);
    g.handle
}
// SAFETY: unique entry receives the ordinary readonly validated startup record;
// the controller's stop is a finite scheduling bound, never authority to an object.
#[unsafe(no_mangle)]
extern "C" fn ev_desktop_main(record: u64, length: u64, stop: u64) -> ! {
    require(
        length == ev_userspace_contract::SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record < (1 << 47) - 4096,
        705,
    );
    // SAFETY: actual loader retains this exact readonly bootstrap page.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    let bootstrap =
        ev_userspace_contract::Bootstrap::parse(bytes).unwrap_or_else(|_| rt::exit(706));
    require(stop > now(), 707);
    #[cfg(feature = "native-bad-shell")]
    {
        // Validate the real ordinary Shell ABI/roles before this measured bad
        // implementation faults. No Ready, fake health/fault marker or IO is sent.
        use ev_userspace_contract::root_v2::{
            catalogue::CHILD_LIMITS,
            graph::{self, Child},
        };
        require(
            CHILD_LIMITS
                .iter()
                .enumerate()
                .all(|(i, value)| bytes[40 + i * 8..48 + i * 8] == value.to_le_bytes())
                && bootstrap.grants().count() == 8,
            810,
        );
        for (index, expected) in graph::grants(Child::Shell).iter().enumerate() {
            let _actual = grant(&bootstrap, index as u64 + 1, expected.kind, expected.rights);
        }
        let address = record - 509 * 4096 + 4 * 1024 * 1024;
        // SAFETY: deliberate user read from this actor's absent device aperture
        // causes real PF14/error4 before ShellReady under the captured controller.
        let value = unsafe { (address as *const u32).read_volatile() };
        rt::exit(811 + u64::from(value));
    }
    #[cfg(all(feature = "display", not(feature = "compositor")))]
    display::run(&bootstrap, record, stop);
    #[cfg(feature = "compositor")]
    compositor::run(&bootstrap, record, stop);
    #[cfg(all(feature = "input", not(feature = "display")))]
    input::run(&bootstrap, record, stop);
    #[cfg(all(
        feature = "shell",
        not(any(feature = "display", feature = "input", feature = "native-bad-shell"))
    ))]
    shell::run(&bootstrap, record, stop);
    #[cfg(all(
        feature = "interactive",
        not(any(feature = "display", feature = "input", feature = "shell"))
    ))]
    interactive::run(&bootstrap, record, stop);
    #[cfg(not(any(
        feature = "display",
        feature = "input",
        feature = "shell",
        feature = "interactive"
    )))]
    app::run(&bootstrap, record, stop);
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(799)
}
