fn main() {
    println!("cargo:rustc-check-cfg=cfg(curve25519_dalek_backend, values(\"serial\"))");
}
