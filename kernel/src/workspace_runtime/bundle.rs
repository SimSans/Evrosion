//! Only the strict physical-run feature includes producer-provided actual
//! inputs. Mechanism-only checks never synthesize images or source provenance.
use super::{Artifact, Assets};
include!(concat!(env!("OUT_DIR"), "/workspace-bundle.rs"));
pub(super) fn assets() -> Assets {
    Assets {
        root: Artifact {
            bytes: M8_ROOT_IMAGE,
            sha256: sha(M8_ROOT_IMAGE),
        },
        manifest: M8_ROOT_MANIFEST,
        measurement: M8_ROOT_MEASUREMENT,
        catalogue: Artifact {
            bytes: M8_CATALOGUE,
            sha256: M8_CAT_SHA,
        },
        images: [
            Artifact {
                bytes: M8_SHELL_IMAGE,
                sha256: M8_SHELL_SHA,
            },
            Artifact {
                bytes: M8_INPUT_IMAGE,
                sha256: M8_INPUT_SHA,
            },
            Artifact {
                bytes: M8_WORKSPACE_IMAGE,
                sha256: M8_WORKSPACE_SHA,
            },
            Artifact {
                bytes: M8_BLOCK_IMAGE,
                sha256: M8_BLOCK_SHA,
            },
            Artifact {
                bytes: M8_DISPLAY_IMAGE,
                sha256: M8_DISPLAY_SHA,
            },
            Artifact {
                bytes: M8_NET_DRIVER_IMAGE,
                sha256: M8_NET_DRIVER_SHA,
            },
            Artifact {
                bytes: M8_NET_SERVICE_IMAGE,
                sha256: M8_NET_SERVICE_SHA,
            },
            Artifact {
                bytes: M8_FILES_IMAGE,
                sha256: M8_FILES_SHA,
            },
            Artifact {
                bytes: M8_EDITOR_IMAGE,
                sha256: M8_EDITOR_SHA,
            },
            Artifact {
                bytes: M8_INSPECTOR_IMAGE,
                sha256: M8_INSPECTOR_SHA,
            },
        ],
        packages: [
            M8_PACKAGE_FILES,
            M8_PACKAGE_EDITOR,
            M8_PACKAGE_INSPECTOR,
            M8_PACKAGE_EDITOR_CANDIDATE,
        ]
        .map(|bytes| Artifact {
            bytes,
            sha256: sha(bytes),
        }),
        placements: M8_PACKAGE_PLACEMENT
            .map(|(bank, offset)| super::assets::Placement { bank, offset }),
        external_ingress: M8_EXTERNAL_INGRESS.map(|bytes| Artifact {
            bytes,
            sha256: sha(bytes),
        }),
    }
}
fn sha(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}
