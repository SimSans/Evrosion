//! Bounded, allocation-free COM1 output for one CPU with interrupts disabled.
use core::fmt;

const COM1: u16 = 0x3f8;
pub struct Serial {
    remaining: usize,
}

fn out(port: u16, byte: u8) {
    // SAFETY: only used by the ring-0 boot/panic path for the reserved COM1 ports.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") byte, options(nomem, nostack));
    }
}

fn input(port: u16) -> u8 {
    let byte;
    // SAFETY: only reads COM1's line status register in the ring-0 boot/panic path.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") byte, options(nomem, nostack));
    }
    byte
}

impl Serial {
    pub fn initialize(budget: usize) -> Self {
        out(COM1 + 1, 0);
        out(COM1 + 3, 0x80);
        out(COM1, 1);
        out(COM1 + 1, 0);
        out(COM1 + 3, 3);
        out(COM1 + 2, 0xc7);
        out(COM1 + 4, 0x0b);
        Self { remaining: budget }
    }

    fn byte(&mut self, byte: u8) -> fmt::Result {
        if self.remaining == 0 {
            return Err(fmt::Error);
        }
        for _ in 0..100_000 {
            if input(COM1 + 5) & 0x20 != 0 {
                out(COM1, byte);
                self.remaining -= 1;
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(fmt::Error)
    }
}

impl fmt::Write for Serial {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for byte in value.bytes() {
            if byte == b'\n' {
                self.byte(b'\r')?;
            }
            self.byte(byte)?;
        }
        Ok(())
    }
}
