//! Compiles the exact active Kernel ABI helper; wrappers contain no reply logic.
#[path = "abi.rs"]
mod abi;
use ev_kernel::user_context::UserContext;
pub fn scalar(f: &mut UserContext, s: u64, v: u64) {
    abi::scalar(f, s, v)
}
pub fn extended(f: &mut UserContext, s: u64, v: u64, n: u64) {
    abi::extended(f, s, v, n)
}
pub fn process_identity(f: &mut UserContext, p: u64, t: u64) {
    abi::process_identity(f, p, t)
}
pub fn event(f: &mut UserContext, v: u64, p: u64, t: u64) {
    abi::event(f, v, p, t)
}
pub fn receive_error(f: &mut UserContext, four: bool, s: u64) {
    abi::receive_error(f, four, s)
}
