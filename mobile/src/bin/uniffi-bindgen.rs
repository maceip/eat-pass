//! Library-mode UniFFI binding generator. Build with `--features cli` and run:
//!   uniffi-bindgen generate --library <path-to-cdylib> --language kotlin --out-dir <dir>
//!   uniffi-bindgen generate --library <path-to-cdylib> --language swift  --out-dir <dir>
fn main() {
    uniffi::uniffi_bindgen_main()
}
