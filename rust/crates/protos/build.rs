fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use vendored protoc to avoid external dependencies on the build host.
    let protoc_path = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc_path);

    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        // Keep file and message names as in Go; package names match.
        .compile(
            &[
                "../../../bbrpc/barter_backup_server.proto",
                "../../../clirpc/barter_backup_client.proto",
                "../../../storedpb/stored.proto",
            ],
            &[
                "../../../bbrpc",
                "../../../clirpc",
                "../../../storedpb",
            ],
        )?;

    Ok(())
}
