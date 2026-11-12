# Retained userspace surface writer

This no_std boundary extracts the M4 RAM writer's fixed 63-page header/pixel/tail
access without adding a safe arbitrary-pointer constructor. Only unsafe
`Surface::from_validated_mapping` can create the owner; it requires the caller's
actual retained initialized RW mapping, sole writer and render-credit lifetime.
A parsed address/extent, startup header or integer capability is not that proof.
The actual loader/controller remains responsible for safe stop before unmap.

Safe methods validate fixed pixel bounds, XRGB bits and nonwrapping header
sequence before mutation, use volatile accesses and return owned values. They
expose no pixel/header references across syscalls. Publish clears exactly the
1984-byte tail. The private raw marker excludes Send/Sync; the type is not Clone
or Copy. Mapping ownership, device quiescence and accepted Present completion
cannot be inferred by this library. A caller must not reuse write credit after
an admitted timeout merely because its wait ended.

Host tests cover syntax rejection without access, exact header/edge pixels,
invalid-counter atomicity and both external guards. Compile-fail examples check
the unsafe construction and thread-bound ownership surface. These are API/model
checks, not a physical PTE, aliasing or device proof.
