# Pre-v4 serializer byte goldens

These files were emitted by compiling the actual pre-v4 SDK from compact
session candidate03, source policy `git-working-tree-v2-no-archived-evidence`,
source SHA256 `8d5b886279a8ebb9b54f7fe53e93da5995ade41408faeacc929597e8dd19750d`.
That private validation snapshot is not a publication revision or network proof.
The v4 serializer did not generate the expected bytes.

- service-startup.bin:336bytes, SHA256 `b323cb18170a46c50b54d27efb33771ef80efb9276b3747f68514a2ea6b52b85`.
- native3-startup.bin:720bytes, SHA256 `6be43864e3df4e2c8a0df2d4025c3e027c51d81a717ae7325e81327804f67993`.
- native3-manifest.bin:912bytes, SHA256 `c577391ab69910b24bbe04994221c439bf7508302721ede89918eadb4ff8d5b1`.

Context is epoch1/incarnation2/process3, limits[16384,512,1,1],manifest4x32,
authority5x32. Service grant is selector1/handle100/MemoryREAD1. Native3 handles
are100..121 in canonical22-role order. Manifest inputs use root image6x32,
catalogue7x32,authority5x32,the same limits,restart3/window60000. Existing
Desktop720/784 byte goldens remain in root_v2/native/fixtures.
