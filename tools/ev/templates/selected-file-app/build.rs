fn main() {
    let path = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("file-app.ld");
    std::fs::write(&path, ev_workspace_client::native_file_app::LINKER_SCRIPT).unwrap();
    println!(
        "cargo:rustc-link-arg-bin=__EV_ENTRY__=-T{}",
        path.display()
    );
    println!("cargo:rustc-link-arg-bin=__EV_ENTRY__=--build-id=none");
}
