# Bounded authenticated time proof

`ev-time-proof` verifies a fixed Cloudflare Roughtime draft11 profile and computes
conservative UTC interval proposals from separately justified elapsed-clock
observations. It is `no_std`, forbids unsafe code, uses fixed bounds and has no
allocator, network client, clock driver or durable state.

This is an internal mechanism. It does not qualify a clock or random source,
authorize an update, commit a replay floor, or implement RFC 10049 version 1.

## Authority and ownership

The authority pin is the independently published Cloudflare UDP2003 key:

```
0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=
```

[The provider documentation](https://developers.cloudflare.com/time-services/roughtime/usage/)
is the pin's source. A relay, DNS result or update server cannot replace it.
Pin rotation needs a separate authenticated policy; the crate has no downloaded
key-replacement API. Loss or change of this provider fails closed.

A caller provides an actual fresh authenticated CSPRNG adapter implementing
`NonceSource`. Merely implementing the trait or returning nonzero bytes does
not qualify entropy. `Client::new` fixes the immutable exchange/window policy before any nonce is
published. `Client::begin` captures the actual elapsed-clock origin
before drawing a nonce. It returns a non-cloneable `Request` while retaining the
matching private pending challenge. An overlapping begin refuses without
redrawing entropy or extending the original exchange. A malformed response,
foreign token, failed signature, old exchange or failed clock observation
consumes the pending challenge. Clock regression or source failure closes the
client. Immediate zero/repeated source outputs also close it; these checks are
not a statistical proof of randomness.

`Request::encode` writes the exact 1024-byte padded request. `Client::finish`
consumes the request and returns an `Anchor` only after checking the actual
immutable response, pending nonce and original exchange cut. There is no public
stateless caller-chosen-nonce verification API. The public historical fixture
exercises cryptography, not current nonce freshness.

Actual transport acceptance, buffer loans, cancellation and cleanup remain the
adapter's responsibility. Consuming or dropping a Rust request does not settle
an accepted network operation, release a loan, refund a nonce or permit replay
of uncertain accepted work. Do not construct or read this borrowed packet from
an untrusted concurrently writable shared window.

## Closed wire profile

The selected protocol is `0x8000000b`, with `ROUGHTIM` framing and a little-endian
body length. Every message is four-byte aligned, has one to eight ordered unique
tags, and contains bounded ordered offsets within its exact extent. The parser
requires these exact numeric tag orders and field lengths:

| Message | Tags |
| --- | --- |
| Reply | `SIG\0`, `VER\0`, `PATH`, `SREP`, `CERT`, `INDX` |
| Certificate | `SIG\0`, `DELE` |
| Delegation | `PUBK`, `MINT`, `MAXT` |
| Signed response | `RADI`, `MIDP`, `ROOT` |

The reply bound is 864 bytes, including framing and at most sixteen 32-byte
Merkle siblings. Unknown tags, versions, lengths, unaligned extents, duplicate
or unordered tags and residual index bits refuse. The observed provider omits
an outer nonce echo; this exact profile does not silently accept future wire
variants or fallback versions.

Both signatures use Ed25519 strict verification. Root and delegated keys must
be canonical, nonweak and torsion-free through `ev-release-trust::PublicKey`.
The exact signed contexts, including their trailing NUL byte, are:

```
RoughTime v1 delegation signature--\0
RoughTime v1 response signature\0
```

The nonce leaf is the first 32 bytes of `SHA-512(0x00 || nonce)`. Each branch is
the first 32 bytes of `SHA-512(0x01 || left || right)`, selected by successive
low index bits. This is truncated SHA-512, not SHA-512/256. The signed root must
match; all remaining index bits must be zero after the path. The midpoint must
lie inside the root-signed delegation interval, and radius must be nonzero and
within the original local policy. Integer overflow refuses.

The exact observed profile and public packet were cross-checked against the
[historical official reference at d09eb373](https://github.com/cloudflare/roughtime/tree/d09eb37366a1861d0c53711ad035d1defa7e3a6a).
That reference ignores residual unsigned index bits; this verifier rejects
them. Its full generator-vector suite failed and is not claimed as passed.
Current reference variants requiring a nonce echo and the different final
[RFC 10049](https://www.rfc-editor.org/rfc/rfc10049.html) are outside this profile.
No reference implementation is copied here.

## Elapsed window and cold floor

The adapter must justify a boot/provider domain and a floor-quantized elapsed
clock whose minimum rate is `num/den` clock seconds per UTC second.
`ClockModel::one_second_floor` validates the finite rational's syntax; it does
not establish that actual hardware or a launcher satisfies it. Neither PIT
interrupt count, ordinary RTC wall time, a synchronized host flag nor an old
fixture establishes this contract.

With original challenge origin `c0` and proposed window end `cThrough`, the
upper elapsed bound is:

```
Emax = ceil((cThrough - c0 + 1) * den / num)
UTC interval = [MIDP - RADI, MIDP + RADI + Emax]
```

The extra second covers floor quantization even for a zero-tick window.
`Policy` fixes exchange age, total anchor age, future window width and radius.
No later call can widen or slide that policy. The first post-crypto observation
must still satisfy the original exchange bound. All windows check original
anchor age, domain, actual observation monotonicity, future order, finite
arithmetic and the supplied committed UTC floor. Every failed window closes
that anchor. A future `through` value is a conservative bound, not an actual
observation; it never advances the last-observed high-water mark.

`Anchor::window` returns only an `IntervalProposal`. It cannot produce
`Time::Qualified`. Only the adapter with actual provider, entropy, clock-rate,
pause/resume and lifecycle evidence may construct the consumer's
`QualifiedWindow` from these exact values. Capture a fresh actual elapsed read
after verification and before the trust-publication decision. Cover the whole
selected decision window, including VM pause and host suspend; using stopped
PIT ticks for this calculation is invalid. Unknown or uncertain time blocks new
remote authorization while installed software and local recovery stay usable.

The proposed next floor is not durable state. Commit it atomically with the
exact accepted trust transaction and retain/reopen it on cold boot. Local
KnownGood rollback must not reset remote metadata or time floors. Whole-medium
malicious rollback resistance is not provided by these helpers.

## Verification and remaining integration

The compact public fixtures under `tests/fixtures` retain request, nonce,
response hashes and origin. Tests verify the actual 352-byte response plus
synthetic real-signed Merkle paths, strict key rejection, malformed packets,
consumed challenges, entropy failures, quantization, clock regression, pause-age
bounds and floor refusal. Synthetic signing secrets are test-only fixtures and
cannot authorize the fixed production pin. SHA-512 uses the existing force-soft
backend; the bare target retains the existing serial Ed25519 backend policy.

The qualified guest RNG/elapsed provider, protected relay, actual freshly
challenged guest response, before-publication pause/resume test, atomic trust
storage and downloaded-object admission remain separate integration gates.
No M6 time, network or update acceptance is established by this library alone.

`Anchor::observe_post_crypto(actualInstant)` separately records a fresh elapsed
read after cryptographic verification. It enforces the original exchange bound,
clock domain, observation high-water and anchor age, closing on any failure.
It returns only `()`: a diagnostic probe without an actual durable trust floor
must not invent floor zero or issue a UTC/Qualified proposal. A later `window`
still needs its actual committed floor, fresh observation and bounded window;
this observation never resets the original anchor age or widens policy.
# Persistent source preparation

`Client::begin_after` prepares the retained nonce source after the adapter's
actual origin capture. It preserves challenge sequence, previous nonce and
elapsed history, refuses preparation while a request is pending, and fences the
Client if preparation fails. The adapter still qualifies its actual entropy and
clock; this API creates no chosen-nonce verifier or UTC authority.
