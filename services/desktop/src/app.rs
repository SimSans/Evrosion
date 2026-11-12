use crate::{event, grant, require, surface::Surface};
#[cfg(not(feature = "app-denied-framebuffer"))]
use crate::{now, yield_now};
#[cfg(not(feature = "app-denied-framebuffer"))]
use ev_graphics::Present;
use ev_graphics::{HelloControl, HelloView, hello};
use ev_userspace_runtime as rt;
pub fn run(b: &ev_userspace_contract::Bootstrap<'_>, record: u64, stop: u64) -> ! {
    require(b.grants().count() == 3, 720);
    let memory = grant(b, 1, 1, 7);
    let present = grant(b, 2, 2, 8);
    #[cfg(feature = "app-denied-framebuffer")]
    let _ = (present, stop);
    let events = grant(b, 3, 2, 8);
    require(rt::inspect(memory, 1).status == 0, 721);
    let denied = rt::call(rt::syscall::DISPLAY_INFO, memory, 1, 0);
    require(
        denied.status == 1 && denied.value == 0 && denied.capability == 0,
        728,
    );
    // The first surface profile admits one App thread. An integer local role
    // cannot create another writer while Display holds the Present credit.
    require(rt::discipline::spawn(1).is_err(), 729);
    let mut surface = Surface::at(record);
    hello(
        &mut surface,
        HelloView {
            focus: HelloControl::OpenFile,
            content: None,
            incarnation: 1,
        },
    )
    .unwrap_or_else(|_| rt::exit(722));
    surface.publish(1);
    surface.tail();
    require(surface.header().sequence == 1, 723);
    event(events, *b"EVGARDY1", stop);
    #[cfg(feature = "app-denied-framebuffer")]
    {
        let address = record - 509 * 4096 + 4 * 1024 * 1024;
        // SAFETY: deliberate absent display-aperture read in an ordinary App root;
        // the contained expected fault proves the device mapping was not delegated.
        let value = unsafe { (address as *const u32).read_volatile() };
        rt::exit(724 + u64::from(value));
    }
    #[cfg(not(feature = "app-denied-framebuffer"))]
    {
        let request = Present(1).request().unwrap();
        let r = rt::call(
            rt::syscall::RPC_CALL,
            present,
            u64::from_le_bytes(request),
            stop,
        );
        require(r.status == 0 && r.capability == 0, 725);
        require(
            Present::parse_reply(r.value.to_le_bytes()) == Ok(Present(1)),
            726,
        );
        event(events, *b"EVGADON1", stop);
        loop {
            require(now() < stop, 727);
            yield_now();
        }
    }
}
