# Bootstrap binding golden vector

`bootstrap-whole-object-v1.bin` is a 232-byte Internal manifest for two grants:
READ to Memory selector 1 and SEND to Endpoint selector 2. The independently
measured image is the three bytes `abc`, **not an executable**. Executable selector
100 and the repeated-byte ABI fingerprint are fixture values.

The kernel fixture creates those roots first, giving object/lineage identities
(0,0) and (1,1). The authority digest is
`9f0dfb790182f40471b2ac1157611c604488c954f4620ebb2cb8396b96dca8cd`;
the manifest digest pinned in the kernel fixture is
`43bc7954f27d9b2759dc89745fd983aaf5c71db41ffdc0c7a177d24e78fede5f`.

`python3 tools/m2/fixture.py` independently encodes the documented format with
Python struct/hashlib and checks exact equality. It does not regenerate artifacts
silently. Neither this file nor its successful test confers production authority.

## Static executable fixture

`bootstrap-static-v1.elf` is an independently encoded 8,200-byte ELF64 ET_EXEC
for the first lower-half user window. It has RX code and RW initialized data plus
three data/BSS pages. Its entry verifies BSS zero fill, initialized data and stack
use, then reaches UD2 at code offset 40; the failure UD2 has a distinct IP. Additional
RX functions at offsets 128/144/160 exercise denied writes/execution and guard
reads. These are finite test functions, not the Root Supervisor.

`bootstrap-static-v1.bin` measures that ELF image and preserves the earlier
manifest's selectors/rights/Job/restart policy. Its digest is
`cd6ccac54eef7702635703c2c41fa44de5cd4ed5b2b1fdbe0e46a71a03037334`;
the image digest is
`ad7f4503b324cf39ae2a086e28de9debed33dded78ecee5e383be4d149977c7b`.
`python3 tools/m2/executable_fixture.py` independently checks both golden files.
