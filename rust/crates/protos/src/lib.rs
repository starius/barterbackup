//! Generated protobuf modules and tonic services for BarterBackup.
//!
//! For reliable builds without requiring `protoc` on the host, we commit the
//! generated Rust code in `src/generated/`. If you want to re-generate, run
//! the helper under `tools/proto-gen` or enable the `gen` feature for this crate.

pub mod bbrpc {
    include!("generated/bbrpc.rs");
}

pub mod clirpc {
    include!("generated/clirpc.rs");
}

pub mod storedpb {
    include!("generated/storedpb.rs");
}
