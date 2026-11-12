//! Narrow x86-64 userspace entry and Internal scalar syscall transport.
//! No allocation, user pointer syscall, authority minting or wire interpretation.
#![no_std]
#![deny(unsafe_code)]

/// Internal syscall numbers shared with the kernel decoder and typed callers.
pub use ev_userspace_contract::syscall;

pub mod cap_echo;
pub mod discipline;
pub mod rpc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub status: u64,
    pub value: u64,
    pub capability: u64,
}

/// Issue the Internal scalar int80 ABI. The kernel validates handles and every
/// operation independently; knowing an object ID or syscall number is no grant.
/// Receive returns payload in RSI and its optional transferred handle in RDX.
/// All other general registers, including RDI, are preserved by the kernel.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(unsafe_code)] // Contained hardware boundary; all operands are scalar values.
pub fn call(number: u64, a: u64, b: u64, c: u64) -> Reply {
    let status;
    let value;
    let capability;
    // SAFETY: this bare-metal userspace ABI preserves every GP register except
    // the declared RAX/RSI/RDX outputs. The instruction dereferences no pointer;
    // trap entry/return and kernel capability enforcement own protected access.
    // No nomem/pure/preserves_flags option hides syscall effects from Rust.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") number => status,
            in("rdi") a,
            inlateout("rsi") b => value,
            inlateout("rdx") c => capability,
            options(nostack),
        );
    }
    Reply {
        status,
        value,
        capability,
    }
}

/// Host policy tests may link this crate but must never issue a host int80 call.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn call(_: u64, _: u64, _: u64, _: u64) -> Reply {
    panic!("Evrosion scalar syscalls require x86-64 bare-metal userspace")
}

/// The capability-only ABI additionally declares R10 as an input/output.
/// `serial` is a protected request/recovery token only on explicitly tagged
/// operations; a nonzero integer alone never establishes capability ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapReply {
    pub status: u64,
    pub value: u64,
    pub capability: u64,
    pub serial: u64,
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(unsafe_code)] // Contained scalar hardware boundary, separate from call().
pub fn call4(number: u64, a: u64, b: u64, c: u64, d: u64) -> CapReply {
    let status;
    let value;
    let capability;
    let serial;
    // SAFETY: this additive capability ABI declares all RAX/RSI/RDX/R10 outputs;
    // kernel trap entry preserves other GP registers. No user pointer is passed.
    // The kernel independently validates authority, request shape and serial.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") number => status,
            in("rdi") a,
            inlateout("rsi") b => value,
            inlateout("rdx") c => capability,
            inlateout("r10") d => serial,
            options(nostack),
        );
    }
    CapReply {
        status,
        value,
        capability,
        serial,
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn call4(_: u64, _: u64, _: u64, _: u64, _: u64) -> CapReply {
    panic!("Evrosion capability syscalls require x86-64 bare-metal userspace")
}

pub fn send(endpoint: u64, bytes: [u8; 8]) -> Reply {
    call(syscall::SEND, endpoint, u64::from_le_bytes(bytes), 0)
}

pub fn receive(endpoint: u64) -> Reply {
    call(syscall::RECEIVE, endpoint, 0, 0)
}

pub fn yield_now() -> Reply {
    call(syscall::YIELD, 0, 0, 0)
}

pub fn inspect(capability: u64, rights: u64) -> Reply {
    call(syscall::INSPECT, capability, rights, 0)
}

/// Read the kernel monotonic clock; successful ticks are returned in Reply.value.
pub fn monotonic() -> Reply {
    call(syscall::MONOTONIC, 0, 0, 0)
}

/// Deadline of this thread's actual protected incoming call; no caller-supplied
/// context can select or extend it. Outside a serving reservation this is denied.
pub fn rpc_deadline() -> Reply {
    call(syscall::RPC_DEADLINE, 0, 0, 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncEndpoint {
    pub endpoint: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncError {
    Status(u64),
    UnexpectedCapability(u64),
}

fn sync_bytes(reply: Reply) -> Result<[u8; 8], SyncError> {
    if reply.status != 0 {
        return Err(SyncError::Status(reply.status));
    }
    if reply.capability != 0 {
        return Err(SyncError::UnexpectedCapability(reply.capability));
    }
    Ok(reply.value.to_le_bytes())
}

impl ev_userspace_contract::echo::SyncTransport for SyncEndpoint {
    type Error = SyncError;

    fn call(&mut self, request: [u8; 8], absolute_deadline: u64) -> Result<[u8; 8], Self::Error> {
        sync_bytes(call(
            syscall::RPC_CALL,
            self.endpoint,
            u64::from_le_bytes(request),
            absolute_deadline,
        ))
    }
}

/// Request process exit. A broken return path faults this userspace process.
#[allow(unsafe_code)] // Only the bare-metal terminal UD2 fallback below.
pub fn exit(code: u64) -> ! {
    call(syscall::EXIT, code, 0, 0);
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    // SAFETY: exit must not return. If it does, an ordinary user #UD prevents
    // executing past this terminal boundary without affecting kernel privilege.
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    panic!("Evrosion process exit unexpectedly returned")
}

/// One literal source for the SysV `_start` ABI and freestanding memory intrinsics.
/// Use `global_asm!(ev_userspace_runtime::start_assembly!())` in an executable
/// defining `extern "C" fn ev_user_main(record: u64, length: u64) -> !`.
#[macro_export]
macro_rules! start_assembly {
    () => {
        r#"
.section .text
.global _start
_start:
    and rsp, -16
    call ev_user_main
    ud2
.global memcpy
memcpy:
    mov rax, rdi
    mov rcx, rdx
    rep movsb
    ret
.global memset
memset:
    mov r8, rdi
    mov eax, esi
    mov rcx, rdx
    rep stosb
    mov rax, r8
    ret
.global memmove
memmove:
    mov rax, rdi
    mov rcx, rdx
    cmp rdi, rsi
    jbe 1f
    test rcx, rcx
    jz 2f
    lea rdi, [rdi+rcx-1]
    lea rsi, [rsi+rcx-1]
    std
    rep movsb
    cld
    ret
1:  rep movsb
2:  ret
.global memcmp
memcmp:
    xor eax, eax
    test rdx, rdx
    jz 2f
1:  movzx eax, byte ptr [rdi]
    movzx ecx, byte ptr [rsi]
    sub eax, ecx
    jne 2f
    inc rdi
    inc rsi
    dec rdx
    jnz 1b
2:  ret
"#
    };
}

pub const START_ASSEMBLY: &str = start_assembly!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_replies_preserve_statuses_and_never_accept_transferred_authority() {
        for status in [1, 2, 3, 4, u64::MAX] {
            assert_eq!(
                sync_bytes(Reply {
                    status,
                    value: 123,
                    capability: 456,
                }),
                Err(SyncError::Status(status))
            );
        }
        assert_eq!(
            sync_bytes(Reply {
                status: 0,
                value: 123,
                capability: 456,
            }),
            Err(SyncError::UnexpectedCapability(456))
        );
        assert_eq!(
            sync_bytes(Reply {
                status: 0,
                value: 0x0102030405060708,
                capability: 0,
            }),
            Ok([8, 7, 6, 5, 4, 3, 2, 1])
        );
    }
}
