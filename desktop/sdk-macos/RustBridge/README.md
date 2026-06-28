# Rust FFI bridge

Copy UniFFI Swift bindings here before building:

```bash
cd eat-pass
./desktop/generate-bindings.sh
```

This copies `mobile/bindings/swift/*` into `RustBridge/` and builds `libeat_pass_mobile.dylib`.

Link path is set in `Package.swift` to `../../../target/debug|release`.
