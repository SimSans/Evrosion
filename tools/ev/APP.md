# Selected file application development

The optional `workspace` frontend provides an Internal standalone application profile. It uses public SDK sources and a closed six-role resource envelope. A reverse-domain `app_id` produces a distinct application identity; it does not make the application the bundled Editor or grant resources.

Create and build a project with explicit SDK and output paths:

```sh
ev app create --root SDK --output NEW_PROJECT --app-id ev.example.file-probe --name "File Probe"
ev app build --root SDK --project NEW_PROJECT --output NEW_BUILD
ev app package --root SDK --project NEW_PROJECT --built NEW_BUILD --output NEW_PACKAGE
ev app verify --root SDK --package NEW_PACKAGE/application.zion --output NEW_VERIFICATION
```

`create` writes a standalone Cargo project, toolchain pin and `ev-workspace.json`. `build` uses the pinned offline toolchain, retains a lockfile, checks project/SDK input hashes before and after compilation, and retains linked ELF, canonical-strip comparison, typed resource-shape admission and stack census. The public linker layout and large code model require the template's explicit `lto = false`; linking against the prebuilt core with LTO enabled is unsupported. This is a measured development build, with the wider E-014 build-platform obligations still open.

`package` requires the same project/SDK inputs as the retained build, produces actual Zion bytes, and checks their complete readback. `verify` checks those bytes, exact metadata, requirements and the selected resource shape. Publisher signatures, installation, running authority and permission decisions remain separate. Current sample evidence uses generated File@2 with a process-private 256-byte buffer; it has no namespace or automatic durable private-data grant.

The following commands currently retain a verified `NOT_APPLIED` request and return failure:

```sh
ev app install --root SDK --package NEW_PACKAGE/application.zion --output NEW_INSTALL_PREFLIGHT
ev app run --root SDK --package NEW_PACKAGE/application.zion --output NEW_RUN_PREFLIGHT
```

Actual installation and launch require the signed Root policy, selected Kernel factory, stable application identity delivery and owner-authorized resources. Host execution does not replace that path. Declaring a capability in metadata grants no authority; an actual selected File endpoint and authenticated caller/lease fix the object and rights. Stable private application data requires a separately scoped owner and persistence path, beyond the sample's private RAM.
