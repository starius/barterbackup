fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only generate when the crate feature `gen` is enabled.
    if std::env::var("CARGO_FEATURE_GEN").is_ok() {
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
    } else {
        println!("cargo:warning=protos: build.rs skipped (feature `gen` not enabled); using committed generated sources");
    }
    Ok(())
}
