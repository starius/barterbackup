use std::path::{Path, PathBuf};
use std::process::Command;

struct GitBuildInfo {
    commit_hash: String,
    commit_date: String,
    dirty: bool,
}

pub fn emit_git_version_for_repo(repo_root: &Path) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", repo_root.join(".git/HEAD").display());
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join(".git/index").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join(".git/packed-refs").display()
    );

    if let Some(head_ref_path) = current_head_ref_path(repo_root) {
        println!("cargo:rerun-if-changed={}", head_ref_path.display());
    }

    let info = git_build_info(repo_root).unwrap_or_else(|| GitBuildInfo {
        commit_hash: "unknown".to_string(),
        commit_date: "unknown".to_string(),
        dirty: false,
    });

    println!("cargo:rustc-env=BB_GIT_COMMIT_HASH={}", info.commit_hash);
    println!("cargo:rustc-env=BB_GIT_COMMIT_DATE={}", info.commit_date);
    println!(
        "cargo:rustc-env=BB_GIT_DIRTY_SUFFIX={}",
        if info.dirty { ", dirty" } else { "" }
    );
}

fn current_head_ref_path(repo_root: &Path) -> Option<PathBuf> {
    let git_dir = repo_root.join(".git");
    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let ref_path = head.strip_prefix("ref: ")?.trim();
    Some(git_dir.join(ref_path))
}

fn git_build_info(repo_root: &Path) -> Option<GitBuildInfo> {
    let commit_hash = run_git(repo_root, &["rev-parse", "--short=12", "HEAD"])?;
    let commit_date = run_git(repo_root, &["show", "-s", "--format=%cs", "HEAD"])?;
    let dirty = !run_git(repo_root, &["status", "--porcelain", "--untracked-files=normal"])?
        .is_empty();
    Some(GitBuildInfo {
        commit_hash,
        commit_date,
        dirty,
    })
}

fn run_git(repo_root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8(output.stdout).ok()?;
    Some(text.trim().to_string())
}
