{
  description = "BarterBackup development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
            extensions = [
              "cargo"
              "clippy"
              "llvm-tools-preview"
              "rust-analyzer"
              "rust-src"
              "rustfmt"
            ];
            targets = [
              "aarch64-unknown-linux-musl"
              "x86_64-pc-windows-msvc"
              "x86_64-unknown-linux-musl"
            ];
          };
        in
        f {
          inherit pkgs rustToolchain system;
        });
    in {
      devShells = forAllSystems ({ pkgs, rustToolchain, system }:
        let
          commonPackages = [
            rustToolchain
            pkgs.arti
            pkgs.cargo-nextest
            pkgs.cargo-deny
            pkgs.cargo-audit
            pkgs.cargo-fuzz
            pkgs.cargo-xwin
            pkgs.cmake
            pkgs.clang
            # Provides clang-format for Makefile proto formatting.
            pkgs.clang-tools
            pkgs.docker-client
            pkgs.git
            pkgs.go
            pkgs.nasm
            pkgs.ninja
            pkgs.openssl
            pkgs.pkg-config
            pkgs.protobuf
            pkgs.protoc-gen-go
            pkgs.protoc-gen-go-grpc
            pkgs.python3
            pkgs.sqlite
            pkgs.tor
            pkgs.pkgsCross.aarch64-multiplatform-musl.stdenv.cc
            pkgs.pkgsCross.musl64.stdenv.cc
          ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.llvmPackages_latest.compiler-rt
            pkgs.lld
          ];
        in {
          default = pkgs.mkShell {
            packages = commonPackages;
            shellHook = ''
              unset CC CXX AR
            '';
          };
          rust = pkgs.mkShell {
            packages = commonPackages;
            shellHook = ''
              unset CC CXX AR
            '';
          };
        });
    };
}
