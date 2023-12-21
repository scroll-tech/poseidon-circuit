{
  description = "Basic devshell for polybase";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [ 
            rustToolchain
            pkg-config
            fontconfig
          ];
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };
      });
}
