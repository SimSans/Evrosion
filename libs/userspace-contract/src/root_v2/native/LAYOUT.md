# Explicit Native Root profile3

This additive safe codec creates no authority or admission receipt. It preserves
Desktop profile1 and ordinary ServiceImage/v1 ABI bytes. Real source/bank/object
ownership, package content compatibility and inactive physical mappings must be
verified by trusted factories before the same Custodian activation path can admit
this profile.

- Version3, record720, profile3, max24 raw syntax grants, exact22 FullGraph roles.
- Base18 selector/kind/rights triples are unchanged.
- ExtraRole19 AppBImage MemoryREAD1;20 PackageA and21 PackageB Memory229
  (READ|MAP|BRANCH);22 BadShellImage MemoryREAD1. They are distinct actual source handles, not catalogue-created capabilities.
- ABI is SHA256 of ABI_DESCRIPTION in native.rs:
  `5614e3153fa598fec13fc6a7078eb8156f3617ea56beafd61be2c952ffcd196c`.
- `manifest_profile(ManifestInputs)` emits912 bytes: header208 +22*32, Native ABI
  at48..80, grant count22, startup/version3/720/profile3 at168..174 and full
  readonly native catalogue SHA256 at176..208. The720-byte startup has no
  independent ABI field; the verified manifest/profile binding supplies it.
- The original Desktop serializers'720/784 fixtures in fixtures/ were emitted
  from retained pre-refactor Rust functions. Tests require exact byte equality.

`Bootstrap::parse/encode` validate profile3 syntax only, including max24, ordering,
no handle aliases and every reserved byte. `FullGraph::parse/encode_full_graph`
require exactly22 and exact role triples; spare slots never widen the profile.
FullGraph exposes handle(base Role), extra(ExtraRole), context, grants and bytes.
No raw/global source authority is derived by these accessors.

## Native readonly catalogue2560

The first1536 bytes are an UNCHANGED, valid legacy catalogue describing the six
component images and PackageA. Its embedded Desktop Root ABI/layout/disk values
apply only to that base component blueprint, never to Native Root admission.
`native::catalogue::Catalogue::base()` is explicitly named as such. Never call
`desktop_plan::verify` to reconstruct a Native manifest from this base alone.
The following1024-byte extension is authoritative for Native ABI/profile/layout:

|Extension offset|Meaning|
|---|---|
|0..8|EVNATV03|
|8..10|extension version3|
|10..12|extension length1024|
|12..14|Native profile3|
|14..16|reserved0|
|16..48|Native ABI|
|48..80|native full-layout measurement|
|80..112|complete PackageB SHA256, distinct from PackageA|
|112..144|PackageB build identity|
|144..152|exact PackageA bytes,1..63*4096|
|152..160|exact PackageB bytes, same bound|
|160..336|176-byte AppB image descriptor record|
|336..512|176-byte BadShell image descriptor, selector22, ordinary Shell ABI/8roles|
|512..514|BootMode u16: Standalone0, SystemManaged1, Recovery2|
|514..1024|reserved0|

AppB record uses selector19; image32, descriptor32, ABI32, limits4*u64 match the
legacy Image wire offsets. Device layout byte136 must0, grant count137 must6,
138..144 zero, roles144..176 exactly match AppA's same six-role wiring. Actual
ELF/descriptor equality and package-ID/executable binding are factory duties;
the codec does not parse executable or package content. Same ELF bytes can be
shared by distinct packages; build identity is not required to differ. BadShell must have a distinct image from the base GoodShell and exactly its roles, ordinary ABI and finite limits; the actual descriptor is independently checked against its measured ELF.

Full2560 bytes fail the old1536 length parser.1536 base bytes alone fail the
Native length parser. Unknown extension/version/profile/ABI, reserved bytes,
wrong AppB descriptor shape and zero/oversized/overflow package lengths refuse.
All bases must name actual nonzero Zion package metadata; DevelopmentSource is
not a substitute for the two complete Native package banks.

Measure the complete2560 bytes using the domain
`evrosion.native.fullgraph.v3\0`, measurement_parts().0,32 zero bytes,
measurement_parts().1, native::layout_description(), and the actual closed
six-child graph wiring description. Only the native measurement field at full
offset1584..1616 is masked. A producer may encode a nonzero temporary field then
hash/re-encode with the actual measurement. Consumers must recompute/compare the
same full measurement and reconstruct ONLY native912 manifest; hashing just the
base or trusting an arbitrary nonzero measurement is insufficient. The codec has
no hashing dependency and does not itself authenticate a supplied digest.

`cohort_parts()` returns three slices around the measurement32 and BootMode2 fields. Hash the first,32 zero bytes,second,2 zero bytes,third with the caller's cohort domain. This makes the exact same content recipe selectable through Managed/Recovery while the raw catalogue, manifest and actual admission still bind the real boot mode. It is not a System admission or health token.

## Fixed bank/layout inputs

`layout_description()`608 bytes names ABI/profile/22 role triples, PackageA pages
384..446 guards383/447, PackageB pages304..366 guards303/367,63-page caps and the
Native disk translation including GrantPolicy wire48..61 to physical96..109. Native Root has8 zero-initialized RW/NX stack pages256..263 (32KiB), guards255/264; other actors retain4 pages and guard260. Its stack words precede roles at description offset256. It contains no live handles/physical pointers. Existing
Words224/232/240 name GrantPolicy wire48, physical96, length14;248..256 remains zero. Root private LOADs must not overlap any bank/guard. Each exact bank length is
rounded up only for owned RAM accounting; initialized tails must be zero, leaves
user RO/NX, and physical claims/receipts remain outside the small LoadedImage
metadata until actual stopped detach/scrub/return.

New `ev_store::native` is a metadata helper only: RootSystem logical0..13 maps
physical16..29;16..29→64..77 registry;32..45→80..93 AppData;48..61→96..109 GrantPolicy. Holes and overflow
refuse. Desktop System still accepts only0..13; File Notes32..45/Private48..61
remain separate and unchanged. No runtime Block profile is exposed by this codec.

## Native3 live authority mechanisms

Opcode44 ENQUEUE_MANAGED_READ uses actual current App ProcessCONTROL, actual
File readonly source, exact managed GrantInbox SEND, and fresh authenticated App
Open nonce inR10. Only actual acceptance consumes that Open; returned ticket is
metadata. No record/path/policy is interpreted by Kernel and no GUI selection is
fabricated. A real dispatch-held target is refused before lineage allocation.
Old41 still requires its actual GUI selection and is unchanged.

Opcode45 INHIBIT_MANAGED_PROCESS is legacy ProcessCONTROL/0/0, preservesR10, and
is Root-only for the actual current App. It checks accepted callee work before
mutation, then holds future dispatch without revoking authority or returning
buffer credit. Existing outbound work completes and wakesReady normally; the
held App cannot run again. Existing37 remains Busy without mutation until real
quiescence. Ordinary stop/revoke/reap and durable policy completion are separate
requirements; inhibition alone is not revocation or permission to reclaim.

Native3 Root ProcessIdentity38 cap0 MUST use call4: RAX=status, RSI=actualPID,
RDX=actualTID, R10=actual captured guest IRQ tick. ChildCONTROL, oldDesktop and
provider preserve their legacyR10 contract. The tick confers no authority.
