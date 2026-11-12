fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=linker-desktop.ld");
    println!("cargo:rerun-if-changed=linker-native.ld");
    if std::env::var_os("CARGO_FEATURE_EXECUTABLE").is_some() {
        let directory = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let script = if std::env::var_os("CARGO_FEATURE_NATIVE_ROOT").is_some() {
            "linker-native.ld"
        } else if std::env::var_os("CARGO_FEATURE_DESKTOP_ROOT").is_some()
            || std::env::var_os("CARGO_FEATURE_PROVIDER_SWITCH").is_some()
            || std::env::var_os("CARGO_FEATURE_IPC_BENCH_ROOT").is_some()
        {
            "linker-desktop.ld"
        } else {
            "linker.ld"
        };
        println!("cargo:rustc-link-arg-bin=ev-root-supervisor=-T{directory}/{script}");
        println!("cargo:rustc-link-arg-bin=ev-root-supervisor=--build-id=none");
    }
}
