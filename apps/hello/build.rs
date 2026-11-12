fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    if std::env::var_os("CARGO_FEATURE_EXECUTABLE").is_some() {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-arg-bin=ev-native-hello=-T{dir}/linker.ld");
        println!("cargo:rustc-link-arg-bin=ev-native-hello=--build-id=none");
    }
}
