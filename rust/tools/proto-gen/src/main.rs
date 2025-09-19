use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = PathBuf::from("../../crates/protos/src/generated");
    std::fs::create_dir_all(&out)?;
    tonic_build::configure()
        .out_dir(&out)
        .protoc_arg("--experimental_allow_proto3_optional")
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

