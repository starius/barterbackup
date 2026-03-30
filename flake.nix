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
              "rust-analyzer"
              "rust-src"
              "rustfmt"
            ];
            targets = [
              "x86_64-unknown-linux-musl"
            ];
          };
        in
        f {
          inherit pkgs rustToolchain;
        });
    in {
      devShells = forAllSystems ({ pkgs, rustToolchain }:
        let
          commonPackages = [
            rustToolchain
            pkgs.cargo-nextest
            pkgs.cargo-deny
            pkgs.cargo-audit
            pkgs.cargo-fuzz
            pkgs.clang
            # Provides clang-format for Makefile proto formatting.
            pkgs.clang-tools
            pkgs.git
            pkgs.openssl
            pkgs.pkg-config
            pkgs.protobuf
            pkgs.sqlite
          ];
        in {
          default = pkgs.mkShell {
            packages = commonPackages;
          };
          rust = pkgs.mkShell {
            packages = commonPackages;
          };
        });
    };
}
