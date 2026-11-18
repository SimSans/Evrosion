//! Volatile access to exact V5 prebound mappings. No shared Rust reference is
//! created or retained across a syscall; the actual adapter/Kernel owns leases.
use super::require;
const BASE: usize = 1usize << 39;
pub struct Window {
    address: usize,
    length: usize,
}
impl Window {
    pub fn at(first: u64, pages: u64) -> Self {
        require(first < 512 && pages > 0 && first + pages <= 512, 1210);
        Self {
            address: BASE + first as usize * 4096,
            length: pages as usize * 4096,
        }
    }
    pub fn read(&self, offset: usize, output: &mut [u8]) {
        require(
            offset
                .checked_add(output.len())
                .is_some_and(|end| end <= self.length),
            1211,
        );
        for (index, byte) in output.iter_mut().enumerate() {
            // SAFETY: strict V5 startup/admission selects this retained exact
            // mapped extent. The current protected sender is blocked in RPC;
            // only bounded volatile bytes are copied into private storage.
            *byte = unsafe { ((self.address + offset + index) as *const u8).read_volatile() };
        }
    }
    pub fn write(&self, offset: usize, input: &[u8]) {
        require(
            offset
                .checked_add(input.len())
                .is_some_and(|end| end <= self.length),
            1212,
        );
        for (index, byte) in input.iter().copied().enumerate() {
            // SAFETY: same retained exact mapping and actual current RPC loan;
            // no client can reuse it until the protected matching reply.
            unsafe { ((self.address + offset + index) as *mut u8).write_volatile(byte) };
        }
    }
    pub fn zero(&self, offset: usize, length: usize) {
        require(
            offset
                .checked_add(length)
                .is_some_and(|end| end <= self.length),
            1213,
        );
        for index in offset..offset + length {
            // SAFETY: checked retained writable extent under this RPC loan.
            unsafe { ((self.address + index) as *mut u8).write_volatile(0) };
        }
    }
    pub fn control_padding_zero(&self) -> bool {
        require(self.length >= 4096, 1214);
        for index in 256..4096 {
            // SAFETY: checked first mapped page. This is untrusted input;
            // refusal does not repair it or invoke a storage operation.
            if unsafe { ((self.address + index) as *const u8).read_volatile() } != 0 {
                return false;
            }
        }
        true
    }
}
impl ev_block_service::store_io::Window for Window {
    fn load(&self, output: &mut ev_workspace_store::Sector) {
        self.read(0, output);
    }
    fn store(&self, input: &ev_workspace_store::Sector) {
        self.write(0, input);
    }
}
