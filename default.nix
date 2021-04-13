{ pkgs ? import <nixpkgs> { } }:
let
  qt = pkgs.qt514;
  python = (pkgs.python37.withPackages(ps: with ps; [
    pyqt5
    scapy
    pyyaml
    black
    mypy
    pre-commit
  ])).override(args: {
    ignoreCollisions = true;
  });
in
pkgs.mkShell {

  buildInputs = with pkgs; [
    poetry
    qt.full
    qtcreator
    python
  ];

  # Keep Poetry cache within development directory
  POETRY_CACHE_DIR = "./.cache/poetry";

  # Just for some extra debug-useful visibility
  QT_DEBUG_PLUGINS = 1;

  LD_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [
    stdenv.cc.cc
    libGL
    zlib
    glib # libgthread-2.0.so
    xorg.libX11 # libX11-xcb.so
    xorg.libxcb # libxcb-shm.so
    xorg.xcbutilwm # libxcb-icccm.so
    xorg.xcbutil # libxcb-util.so
    xorg.xcbutilimage # libxcb-image.so
    xorg.xcbutilkeysyms # libxcb-keysyms.so
    xorg.xcbutilrenderutil # libxcb-renderutil.so
    xorg.xcbutilrenderutil # libxcb-renderutil.so
    dbus # libdbus-1.so
    libxkbcommon # libxkbcommon-x11.so
    fontconfig
    freetype
  ];
}
