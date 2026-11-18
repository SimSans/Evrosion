fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    if std::env::var_os("CARGO_FEATURE_NATIVE_ACTOR").is_some() {
        let directory = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-arg-bin=ev-workspace-root=-T{directory}/linker.ld");
        println!("cargo:rustc-link-arg-bin=ev-workspace-root=--build-id=none");
    }
}
