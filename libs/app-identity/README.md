# Canonical stable application key

This safe `no_std` crate owns the opaque 16-byte `AppId` used by `.zion` manifests,
the trusted application registry and selected-file policy. A key is a claimed
registry identity, not a publisher principal, package/build hash or live process.
Constructing or parsing it supplies no authority to assume an existing identity.
Trusted installation and update policy must resolve that separately.
