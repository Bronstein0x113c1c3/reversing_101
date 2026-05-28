{ pkgs ? import <nixpkgs> { } }:

with pkgs;

mkShell {
  buildInputs = [
    go
    gcc
    gotools
    gopls
    delve
    pkg-config
    alsa-lib
    portaudio
    mpg123
    libmsquic
    rustup
    openssl
    cmake
  ];
}

