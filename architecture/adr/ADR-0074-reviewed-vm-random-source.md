# ADR-0074 — Reviewed developer-VM random source

Status: Accepted bounded VM adapter design; actual linked/guest qualification pending

Date: 2026-11-12

Decision level: B

## Decision and trust boundary

For the owner-approved VM developer alpha, use the reviewed QEMU TCG random
path as input to the private generator from ADR-0071. This selects a particular
trusted-host development profile, not generic physical-CPU RDRAND qualification
or proof against a hostile hypervisor. The exact installed QEMU binary matched
the official package. Reviewed helper/source and binary-call witnesses establish
its normal TCG RDRAND path through `qemu_guest_getrandom` to GnuTLS
`GNUTLS_RND_RANDOM`. Deterministic seed/replay paths are separate and excluded.

The trusted host runner checks the actual executable hash and a closed launch
argument profile before spawning the VM. Require explicit Q35/TCG, CPUmax,
single CPU, no user config and the fixed assigned NIC; reject unknown switches,
alternative accelerators/CPUs, seed, replay, snapshot restore, config, plugin
and global overrides. Remove inherited dynamic-loader/plugin injection hooks.
Record the exact executed arguments and qualification receipt. The owner-controlled
host OS, loader and system crypto libraries remain trust assumptions, not
measured host attestation. Reproducible catalogue bytes use tracked reference
inputs; never insert the current build host's binary hash into guest artifacts.

The guest private Root adapter independently checks the expected catalogue
binary digest, actual RDRAND feature and actual TCG CPUID signature. Those
checks do not prove host launch arguments; the trusted runner supplies that
separate prerequisite. Obtain four successful64-bit words, checking actual CF
and limiting each word to10 attempts. Numeric zero is a valid successful word.
Erase partial seeds on any failure. Seed the existing reviewed ChaCha20 wrapper,
erase its input and retain the generator under the actual Root incarnation.
No raw-word API, saved-ready bit, deterministic fallback or caller-nominated
seed supplies adequate entropy. Failures fence previous eligibility.

Use only actual generator output for a Root-authorized network initialization.
Do not log raw seed/output or claim that a nonzero seed label proves adequacy.
Retain finite generation/request/output/reseed accounting and physical private
memory ownership through actual quiescence and scrubbing.

## Evidence and limits

The package/source/binary review receipt is retained in
the local engineering archive,
SHA-256 `409de274e013287877b7a2762075c65e4ff535cfea624ea0ee3d5b7e4ffeba9d`.
This review is not a full source rebuild or entropy certification. The earlier
random-platform source is not the selected Linux binary backend; GnuTLS is.

Ten generator/acquisition tests and strict host/bare-metal checks pass, including
bounded failure, partial erasure, successful zero, output/time exhaustion and
clock/sequence failures. The host qualifier rejects deterministic/alternate
launch inputs. Actual Root linking, exact page/stack/Job admission, executed
guest acquisition, missing-source injection and cold-state proofs remain open.
The host RTC selection explicitly does not qualify a UTC provider; M6-05 remains
open. This changes no physical hardware release gate or personal-disk authority.

Primary references: [QEMU CPUID implementation](https://raw.githubusercontent.com/qemu/qemu/v10.2.1/target/i386/cpu.c),
[QEMU launch options](https://qemu-project.gitlab.io/qemu/system/invocation.html),
and [Intel's CF/feature/retry contract](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html).
