fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    if std::env::var_os("CARGO_FEATURE_EXECUTABLE").is_some() {
        let directory = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-arg-bin=ev-native-files=-T{directory}/linker.ld");
        println!("cargo:rustc-link-arg-bin=ev-native-files=--build-id=none");
    }
}
