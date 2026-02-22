// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "HardlyLost",
    products: [
        .executable(name: "HardlyLost", targets: ["HardlyLost"]),
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "HardlyLost",
            dependencies: [],
            linkerSettings: [
                .linkedLibrary("z")
            ]
        ),
    ]
)
