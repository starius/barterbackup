{
  description = "BarterBackup development environment and package";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      lib = nixpkgs.lib;
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = f: lib.genAttrs systems (system:
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
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
          staticTarget =
            if system == "x86_64-linux" then "x86_64-unknown-linux-musl"
            else if system == "aarch64-linux" then "aarch64-unknown-linux-musl"
            else null;
          crossCc =
            if system == "x86_64-linux" then pkgs.pkgsCross.musl64.stdenv.cc
            else if system == "aarch64-linux" then pkgs.pkgsCross.aarch64-multiplatform-musl.stdenv.cc
            else null;
          staticTargetEnv =
            if staticTarget == null then null
            else lib.toUpper (lib.replaceStrings [ "-" ] [ "_" ] staticTarget);
          linker =
            if staticTarget == null then null
            else "${crossCc}/bin/${staticTarget}-gcc";
          archiver =
            if staticTarget == null then null
            else "${crossCc}/bin/${staticTarget}-ar";
        in
        f {
          inherit crossCc;
          inherit
            archiver
            linker
            pkgs
            rustPlatform
            rustToolchain
            staticTarget
            staticTargetEnv
            system
            ;
        });
    in {
      packages = forAllSystems ({
        crossCc,
        archiver,
        linker,
        pkgs,
        rustPlatform,
        rustToolchain,
        staticTarget,
        staticTargetEnv,
        ...
      }:
        let
          version = "0.1.0";
          package = if staticTarget == null then null else rustPlatform.buildRustPackage {
            pname = "barterbackup";
            inherit version;

            src = self;
            cargoLock.lockFile = ./Cargo.lock;

            cargoBuildTarget = staticTarget;
            doCheck = false;
            strictDeps = true;

            nativeBuildInputs = [ rustToolchain crossCc ];

            CARGO_BUILD_PIPELINING = "false";
            RUSTFLAGS = "-Zmir-opt-level=0";
            "CARGO_TARGET_${staticTargetEnv}_LINKER" = linker;
            "AR_${staticTargetEnv}" = archiver;

            buildPhase = ''
              runHook preBuild
              cargo build --offline --release --target ${staticTarget} -p bbd -p bbcli
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall

              mkdir -p \
                $out/bin \
                $out/share/bash-completion/completions \
                $out/share/doc/barterbackup/cli \
                $out/share/fish/vendor_completions.d \
                $out/share/man/man1 \
                $out/share/barterbackup/completions \
                $out/share/zsh/site-functions

              install -Dm755 target/${staticTarget}/release/bbd $out/bin/bbd
              install -Dm755 target/${staticTarget}/release/bbcli $out/bin/bbcli

              install -Dm644 docs/man/bbd.1 $out/share/man/man1/bbd.1
              install -Dm644 docs/man/bbcli.1 $out/share/man/man1/bbcli.1

              install -Dm644 docs/cli/bbd.md $out/share/doc/barterbackup/cli/bbd.md
              install -Dm644 docs/cli/bbcli.md $out/share/doc/barterbackup/cli/bbcli.md

              install -Dm644 completions/bbd.bash \
                $out/share/bash-completion/completions/bbd
              install -Dm644 completions/bbcli.bash \
                $out/share/bash-completion/completions/bbcli
              install -Dm644 completions/bbd.fish \
                $out/share/fish/vendor_completions.d/bbd.fish
              install -Dm644 completions/bbcli.fish \
                $out/share/fish/vendor_completions.d/bbcli.fish
              install -Dm644 completions/bbd.zsh \
                $out/share/zsh/site-functions/_bbd
              install -Dm644 completions/bbcli.zsh \
                $out/share/zsh/site-functions/_bbcli

              install -Dm644 completions/bbd.elvish \
                $out/share/barterbackup/completions/bbd.elvish
              install -Dm644 completions/bbcli.elvish \
                $out/share/barterbackup/completions/bbcli.elvish
              install -Dm644 completions/bbd.ps1 \
                $out/share/barterbackup/completions/bbd.ps1
              install -Dm644 completions/bbcli.ps1 \
                $out/share/barterbackup/completions/bbcli.ps1

              runHook postInstall
            '';

            meta = {
              description = "Encrypted peer-to-peer backup daemon and CLI";
              mainProgram = "bbcli";
              platforms = [ "x86_64-linux" "aarch64-linux" ];
            };
          };
        in
        lib.optionalAttrs (package != null) {
          barterbackup = package;
          default = package;
        });

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
            pkgs.docker
            pkgs.gnumake
            pkgs.git
            pkgs.go
            pkgs.nasm
            pkgs.ninja
            pkgs.openssl
            pkgs.pkg-config
            pkgs.protobuf
            pkgs.protoc-gen-go
            pkgs.protoc-gen-go-grpc
            (pkgs.python3.withPackages (ps: [
              ps.cryptography
              ps.paramiko
              ps.tomli-w
              ps.typeguard
              ps.typing-extensions
            ]))
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
