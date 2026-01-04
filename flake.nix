{
  description = "BarterBackup development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        f pkgs);
    in {
      devShells = forAllSystems (pkgs: {
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
      });
    };
}
