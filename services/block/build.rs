fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=store-linker.ld");
    if std::env::var_os("CARGO_FEATURE_EXECUTABLE").is_some() {
        let directory = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let script = if std::env::var_os("CARGO_FEATURE_TEST_STORE_CLIENT").is_some() {
            "store-linker.ld"
        } else {
            "linker.ld"
        };
        println!("cargo:rustc-link-arg-bin=ev-block-service=-T{directory}/{script}");
        println!("cargo:rustc-link-arg-bin=ev-block-service=--build-id=none");
    }
}
