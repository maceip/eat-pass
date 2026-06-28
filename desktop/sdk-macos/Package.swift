// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "EatPassDesktop",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "EatPassDesktop", targets: ["EatPassDesktop"]),
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
            name: "EatPassDesktop",
            dependencies: ["EatPassMobileRust"],
            path: "Sources/EatPassDesktop"
        ),
    ]
)
