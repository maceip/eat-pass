#!/usr/bin/env bash
# Build native PoMFRIT dependencies (MAYO-C + VOLE-in-the-head).
#
# Platform: Linux x86_64 with AVX2 (AES-NI, PCLMUL). Will not build on macOS/ARM.
#
# Toolchain matches pq_blind_signatures/manual-installation.md:
#   gcc/g++ >= 14.2   (Ubuntu 24.04: apt install gcc-14 g++-14)
#   meson >= 1.7      (apt meson is too old — pipx install meson)
#   ninja >= 1.12     (pipx install ninja)
#   git, make         (build-essential)
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PQ="$ROOT/third_party/pq_blind_signatures"

version_ge() {
  local have="$1" need="$2"
  [[ "$(printf '%s\n' "$need" "$have" | sort -V | head -1)" == "$need" ]]
}

require_linux_x86_64() {
  local uname_s uname_m
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"
  if [[ "$uname_s" != "Linux" || "$uname_m" != "x86_64" ]]; then
    cat >&2 <<EOF
PoMFRIT native code requires Linux x86_64 (got ${uname_s}/${uname_m}).
Build on an Azure CVM or: docker run --platform linux/amd64 -v "\$PWD:/eat-pass" -w /eat-pass ubuntu:24.04 bash scripts/build-pomfrit-deps.sh
EOF
    exit 1
  fi
}

pick_compiler() {
  if command -v gcc-14 >/dev/null && command -v g++-14 >/dev/null; then
    export CC=gcc-14
    export CXX=g++-14
  elif command -v gcc >/dev/null && command -v g++ >/dev/null; then
    export CC=gcc
    export CXX=g++
  else
    echo "gcc/g++ required (Ubuntu: apt install gcc-14 g++-14 build-essential)" >&2
    exit 1
  fi
  local ver
  ver="$("$CXX" -dumpfullversion 2>/dev/null || "$CXX" -dumpversion)"
  if ! version_ge "$ver" "14.0"; then
    echo "g++ >= 14 required (have $ver). Ubuntu: apt install gcc-14 g++-14" >&2
    exit 1
  fi
}

require_meson() {
  if ! command -v meson >/dev/null; then
    cat >&2 <<'EOF'
meson >= 1.7 required (apt meson on Ubuntu is too old).
  sudo apt install pipx && pipx ensurepath
  pipx install meson ninja
EOF
    exit 1
  fi
  local ver
  ver="$(meson --version)"
  if ! version_ge "$ver" "1.7"; then
    echo "meson >= 1.7 required (have $ver). Install: pipx install meson" >&2
    exit 1
  fi
}

require_ninja() {
  if ! command -v ninja >/dev/null; then
    echo "ninja required. Install: pipx install ninja" >&2
    exit 1
  fi
  local ver
  ver="$(ninja --version)"
  if ! version_ge "$ver" "1.12"; then
    echo "ninja >= 1.12 required (have $ver). Install: pipx install ninja" >&2
    exit 1
  fi
}

require_linux_x86_64
pick_compiler
require_meson
require_ninja
command -v make >/dev/null || { echo "make required (apt install build-essential)" >&2; exit 1; }
command -v git >/dev/null || { echo "git required" >&2; exit 1; }

echo "PoMFRIT toolchain: CC=$CC ($("$CC" --version | head -1)) meson=$(meson --version) ninja=$(ninja --version)"

cd "$PQ/mayo-c-sys" && make
cd "$PQ/vole-mayo-sys" && make
echo "PoMFRIT native libs: $PQ/mayo-c-sys/target/debug/libmayo.so $PQ/vole-mayo-sys/target/debug/libvolemayo.so"
