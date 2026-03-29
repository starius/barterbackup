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
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
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
      devShells = forAllSystems ({ pkgs, rustToolchain }: {
        default =
          let
            goToolchain = if pkgs ? go_1_25 then pkgs.go_1_25 else pkgs.go;
          in
          pkgs.mkShell {
            packages = [
              goToolchain
              pkgs.protobuf
              pkgs.protoc-gen-go
              pkgs.protoc-gen-go-grpc
              pkgs.clang-tools
            ];
            env = {
              CGO_ENABLED = "0";
            };
          };
        rust = pkgs.mkShell {
          packages = [
            rustToolchain
            pkgs.cargo-nextest
            pkgs.cargo-deny
            pkgs.cargo-audit
            pkgs.cargo-fuzz
            pkgs.clang
            pkgs.git
            pkgs.openssl
            pkgs.pkg-config
            pkgs.protobuf
            pkgs.rsync
            pkgs.sqlite
          ];
        };
      });
    };
}
