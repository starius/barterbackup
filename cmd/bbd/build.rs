include!("../../build/git_version.rs");

fn main() {
    emit_git_version_for_repo(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("cmd/bbd lives two directories below the repo root"),
    );
}
