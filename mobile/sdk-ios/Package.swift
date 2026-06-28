// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "EatPassMobile",
    platforms: [.iOS(.v14)],
    products: [
        .library(name: "EatPassMobile", targets: ["EatPassMobile"]),
    ],
    targets: [
        .target(
            name: "EatPassMobileRust",
            path: "RustBridge",
            publicHeadersPath: ".",
            linkerSettings: [
                .linkedLibrary("eat_pass_mobile"),
                .unsafeFlags([
                    "-L", "../../../target/debug",
                    "-L", "../../../target/release",
                ]),
            ]
        ),
        .target(
            name: "EatPassMobile",
            dependencies: ["EatPassMobileRust"],
            path: "Sources/EatPassMobile"
        ),
    ]
)
