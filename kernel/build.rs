fn main() {
    println!("cargo:rustc-check-cfg=cfg(ev_shared_active_mutation_probe)");
    let directory =
        std::env::var("CARGO_MANIFEST_DIR").expect("Cargo supplies the manifest directory");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-env-changed=EVROSION_BUILD_ID");
    println!("cargo:rerun-if-env-changed=EVROSION_SOURCE_SHA256");
    println!("cargo:rustc-link-arg-bin=evrosion-kernel=-T{directory}/linker.ld");
    println!("cargo:rustc-link-arg-bin=evrosion-kernel=--build-id=none");
    println!("cargo:rerun-if-env-changed=EVROSION_SUPERVISOR_BUNDLE");
    let output =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("supervisor-bundle.rs");
    if let Some(bundle) = std::env::var_os("EVROSION_SUPERVISOR_BUNDLE") {
        println!(
            "cargo:rerun-if-changed={}",
            std::path::Path::new(&bundle).display()
        );
        std::fs::copy(bundle, output).expect("copy measured supervisor bundle");
    } else {
        // Direct host/target lint needs no embedded artifact. Such a binary must
        // refuse supervisor boot; only the recorded frontend supplies a bundle.
        let mut stub = String::new();
        stub += "#[cfg(feature=\"test-m5-ipc-bench\")] pub const M5_IPC_ROOT_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m5-ipc-bench\")] pub const M5_IPC_ROOT_MANIFEST:&[u8]=&[];#[cfg(feature=\"test-m5-ipc-bench\")] pub const M5_IPC_ROOT_MEASUREMENT:[u8;32]=[0;32];";
        for name in ["M5_IPC_SERVER", "M5_IPC_CLIENT"] {
            stub += &format!(
                "#[cfg(feature=\"test-m5-ipc-bench\")] pub const {name}_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m5-ipc-bench\")] pub const {name}_SHA:[u8;32]=[0;32];#[cfg(feature=\"test-m5-ipc-bench\")] pub const {name}_DESCRIPTOR:[u8;32]=[0;32];"
            );
        }

        for name in [
            "NORMAL",
            "FAULT",
            "GRAPH",
            "GRAPH_FAULT",
            "GRAPH_RPC",
            "GRAPH_RPC_TIMEOUT",
            "GRAPH_RESTART",
            "CUSTODY_GRAPH",
            "CUSTODY_EXIT",
            "CUSTODY_WATCHDOG",
            "RECOVERY",
        ] {
            stub += &format!(
                "pub const {name}_IMAGE:&[u8]=&[];pub const {name}_MANIFEST:&[u8]=&[];pub const {name}_MEASUREMENT:[u8;32]=[0;32];"
            );
        }
        for name in [
            "CUSTODY_CORRUPT_MANIFEST",
            "CUSTODY_CORRUPT_IMAGE",
            "CUSTODY_WRONG_AUTHORITY_MANIFEST",
        ] {
            stub += &format!("pub const {name}:&[u8]=&[];");
        }
        stub += "pub const CUSTODY_WRONG_AUTHORITY_MEASUREMENT:[u8;32]=[0;32];";
        for name in [
            "ECHO",
            "ECHO_FAULT",
            "ECHO_DELAY",
            "ECHO_SELECTIVE",
            "IPC_CHAIN",
            "IPC_DEPTH",
            "CAP_CLIENT_NORMAL",
            "CAP_CLIENT_TIMEOUT",
            "CAP_CLIENT_DEATH",
            "CAP_CLIENT_QUEUED_TIMEOUT",
            "CAP_CLIENT_QUEUED_DEATH",
            "CAP_SERVER_NORMAL",
            "CAP_SERVER_DELAY",
            "CAP_SERVER_FAULT",
            "CAP_SERVER_HOLD",
            "CAP_SERVER_QUEUED_FAULT",
        ] {
            stub +=
                &format!("pub const {name}_IMAGE:&[u8]=&[];pub const {name}_SHA:[u8;32]=[0;32];");
        }
        for name in [
            "M3_PIO_WRITE",
            "M3_PIO_VERIFY",
            "M3_PIO_DIRECT",
            "M3_BLOCK_CLIENT_WRITE",
            "M3_BLOCK_CLIENT_VERIFY",
            "M3_BLOCK_DRIVER",
        ] {
            stub += &format!(
                r#"#[cfg(any(feature="test-m3-pio-write",feature="test-m3-pio-verify"))] pub const {name}_IMAGE:&[u8]=&[];#[cfg(any(feature="test-m3-pio-write",feature="test-m3-pio-verify"))] pub const {name}_SHA:[u8;32]=[0;32];"#
            );
        }
        stub += "#[cfg(feature=\"test-m3-store\")]pub const M3_STORE_CLIENT_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m3-store\")]pub const M3_STORE_CLIENT_SHA:[u8;32]=[0;32];";
        stub += "#[cfg(feature=\"test-m3-generation\")]pub const M3_GENERATION_CLIENT_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m3-generation\")]pub const M3_GENERATION_CLIENT_SHA:[u8;32]=[0;32];#[cfg(feature=\"test-m3-generation\")]pub const M3_GENERATION_CATALOGUE:&[u8]=&[];#[cfg(feature=\"test-m3-generation\")]pub const M3_GENERATION_CATALOGUE_SHA:[u8;32]=[0;32];";
        stub += "#[cfg(feature=\"test-m3-owner\")]pub const M3_OWNER_CLIENT_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m3-owner\")]pub const M3_OWNER_CLIENT_SHA:[u8;32]=[0;32];#[cfg(feature=\"test-m3-owner\")]pub const M3_OWNER_CATALOGUE:&[u8]=&[];#[cfg(feature=\"test-m3-owner\")]pub const M3_OWNER_CATALOGUE_SHA:[u8;32]=[0;32];";
        stub += "#[cfg(feature=\"test-m3-progress\")]pub const M3_PROGRESS_CLIENT_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m3-progress\")]pub const M3_PROGRESS_CLIENT_SHA:[u8;32]=[0;32];#[cfg(feature=\"test-m3-progress\")]pub const M3_PROGRESS_CATALOGUE:&[u8]=&[];#[cfg(feature=\"test-m3-progress\")]pub const M3_PROGRESS_CATALOGUE_SHA:[u8;32]=[0;32];#[cfg(feature=\"test-m3-progress\")]pub const GENERATION_SILENT_IMAGE:&[u8]=&[];";
        for name in ["M3_FILE_SERVER", "M3_FILE_APP"] {
            stub += &format!(
                "#[cfg(feature=\"test-m3-file\")]pub const {name}_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m3-file\")]pub const {name}_SHA:[u8;32]=[0;32];"
            );
        }
        for name in [
            "M4_DISPLAY_APP",
            "M4_DISPLAY_SERVER",
            "M4_DISPLAY_APP_DENIED",
            "M4_DISPLAY_SERVER_DENIED",
        ] {
            stub += &format!(
                "#[cfg(feature=\"test-m4-display\")]pub const {name}_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m4-display\")]pub const {name}_SHA:[u8;32]=[0;32];"
            );
        }
        for name in ["GENERATION_GOOD", "GENERATION_BAD"] {
            stub +=
                &format!("#[cfg(feature=\"test-m3-generation\")]pub const {name}_IMAGE:&[u8]=&[];");
        }
        // Only coordinated desktop builds provide actual measured assets.
        for name in ["SHELL", "INPUT", "FILE", "BLOCK", "APP", "DISPLAY"] {
            stub += &format!(
                "#[cfg(all(feature=\"test-m4-desktop\",not(feature=\"test-m5-native\")))]pub const M4_DESKTOP_{name}_IMAGE:&[u8]=&[];#[cfg(all(feature=\"test-m4-desktop\",not(feature=\"test-m5-native\")))]pub const M4_DESKTOP_{name}_SHA:[u8;32]=[0;32];"
            );
        }
        stub += "#[cfg(all(feature=\"test-m4-desktop\",not(feature=\"test-m5-native\")))]pub const M4_DESKTOP_ROOT_IMAGE:&[u8]=&[];#[cfg(all(feature=\"test-m4-desktop\",not(feature=\"test-m5-native\")))]pub const M4_DESKTOP_ROOT_MANIFEST:&[u8]=&[];#[cfg(all(feature=\"test-m4-desktop\",not(feature=\"test-m5-native\")))]pub const M4_DESKTOP_ROOT_MEASUREMENT:[u8;32]=[0;32];#[cfg(all(feature=\"test-m4-desktop\",not(feature=\"test-m5-native\")))]pub const M4_DESKTOP_CATALOGUE:&[u8]=&[];#[cfg(all(feature=\"test-m4-desktop\",not(feature=\"test-m5-native\")))]pub const M4_DESKTOP_CATALOGUE_SHA:[u8;32]=[0;32];#[cfg(all(feature=\"test-m4-desktop\",not(feature=\"test-m5-native\")))]pub const M4_DESKTOP_APP_PACKAGE:&[u8]=&[];";
        for name in [
            "SHELL",
            "INPUT",
            "FILE",
            "BLOCK",
            "APP_A",
            "APP_B",
            "DISPLAY",
            "BAD_SHELL",
        ] {
            stub += &format!(
                "#[cfg(feature=\"test-m5-native\")]pub const M5_NATIVE_{name}_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m5-native\")]pub const M5_NATIVE_{name}_SHA:[u8;32]=[0;32];"
            );
        }
        for name in [
            "ROOT_IMAGE",
            "ROOT_MANIFEST",
            "CATALOGUE",
            "PACKAGE_A",
            "PACKAGE_B",
        ] {
            stub +=
                &format!("#[cfg(feature=\"test-m5-native\")]pub const M5_NATIVE_{name}:&[u8]=&[];");
        }
        for name in ["ROOT_MEASUREMENT", "CATALOGUE_SHA"] {
            stub += &format!(
                "#[cfg(feature=\"test-m5-native\")]pub const M5_NATIVE_{name}:[u8;32]=[0;32];"
            );
        }
        // Empty lint-only assets cannot satisfy physical provider admission.
        for name in ["CONSUMER", "A", "B"] {
            stub += &format!(
                "#[cfg(feature=\"test-m5-provider\")]pub const M5_PROVIDER_{name}_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m5-provider\")]pub const M5_PROVIDER_{name}_SHA:[u8;32]=[0;32];#[cfg(feature=\"test-m5-provider\")]pub const M5_PROVIDER_{name}_DESCRIPTOR:[u8;32]=[0;32];"
            );
        }
        stub += "#[cfg(feature=\"test-m5-provider\")]pub const M5_PROVIDER_ROOT_IMAGE:&[u8]=&[];#[cfg(feature=\"test-m5-provider\")]pub const M5_PROVIDER_ROOT_MANIFEST:&[u8]=&[];#[cfg(feature=\"test-m5-provider\")]pub const M5_PROVIDER_ROOT_MEASUREMENT:[u8;32]=[0;32];";
        std::fs::write(output, stub).unwrap();
    }
}
