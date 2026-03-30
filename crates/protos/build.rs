fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Rebuild generated stubs whenever any source proto changes.
    for proto in [
        "../../bbrpc/barter_backup_server.proto",
        "../../clirpc/barter_backup_client.proto",
        "../../storedpb/stored.proto",
    ] {
        println!("cargo:rerun-if-changed={proto}");
    }

    // Use vendored protoc to avoid external dependencies on the build host.
    let protoc_path = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc_path);

    // Compile protos with tonic-prost-build (tonic 0.14).
    tonic_prost_build::configure()
        .build_server(true)
        .compile_protos(
            &[
                "../../bbrpc/barter_backup_server.proto",
                "../../clirpc/barter_backup_client.proto",
                "../../storedpb/stored.proto",
            ],
            &["../../bbrpc", "../../clirpc", "../../storedpb"],
        )?;
    Ok(())
}
