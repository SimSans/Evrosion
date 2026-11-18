//! Generated-source compatibility only. Never mutates retained producer input.
pub fn with_optional_ingress(mut bytes: Vec<u8>) -> Vec<u8> {
    const DECLARATION: &[u8] = b"pub const M8_EXTERNAL_INGRESS:";
    if !bytes
        .windows(DECLARATION.len())
        .any(|part| part == DECLARATION)
    {
        bytes.extend_from_slice(b"\n// Legacy producer source: no optional ingress blob. Occupied catalogue still refuses in Assets.\npub const M8_EXTERNAL_INGRESS:Option<&[u8]>=None;\n");
    }
    bytes
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_source_prefix_is_exact_and_only_explicit_none_is_appended() {
        let old = b"pub const M8_PACKAGE_FILES:&[u8]=&[1,2,3];\n";
        let adapted = with_optional_ingress(old.to_vec());
        assert!(adapted.starts_with(old));
        assert!(adapted.ends_with(b"pub const M8_EXTERNAL_INGRESS:Option<&[u8]>=None;\n"));
        assert_eq!(with_optional_ingress(adapted.clone()), adapted);
    }
    #[test]
    fn explicit_some_or_none_is_preserved_byte_exact() {
        for old in [
            b"pub const M8_EXTERNAL_INGRESS:Option<&[u8]>=None;".as_slice(),
            b"pub const M8_EXTERNAL_INGRESS:Option<&[u8]>=Some(include_bytes!(\"actual.zion\"));",
        ] {
            assert_eq!(with_optional_ingress(old.to_vec()), old);
        }
    }
}
