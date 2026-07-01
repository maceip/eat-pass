#!/usr/bin/env bash
# Full `cargo test --workspace` when PoMFRIT cannot build locally (macOS/ARM).
#
# Prefer, in order:
#   1. Linux x86_64 host / Azure CVM (native AVX2)
#   2. SSH to uqaz1:  EAT_PASS_REMOTE=azureuser@attest.secure.build ./scripts/test-workspace-linux-docker.sh
#   3. Docker linux/amd64 on Apple Silicon often lacks AVX2 for PoMFRIT — may fail
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE="${EAT_PASS_REMOTE:-}"

if [[ -n "$REMOTE" ]]; then
  echo "=== eat-pass workspace tests (remote $REMOTE) ==="
  REMOTE_DIR="${EAT_PASS_REMOTE_DIR:-eat-pass-test}"
  rsync -az --delete \
    --exclude target \
    --exclude third_party/pq_blind_signatures/mayo-c-sys/target \
    --exclude third_party/pq_blind_signatures/vole-mayo-sys/target \
    --exclude third_party/pq_blind_signatures/vole/faest-cpp-tmp/build \
    --exclude third_party/pq_blind_signatures/vole/faest-cpp-tmp/build_debug \
    -e ssh "$ROOT/" "$REMOTE:~/$REMOTE_DIR/"
  ssh -o BatchMode=yes "$REMOTE" bash -s <<REMOTE_EOF
set -euo pipefail
export PATH="\$HOME/.local/bin:\$HOME/.cargo/bin:\$PATH"
cd "\$HOME/${REMOTE_DIR}"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libclang-dev 2>/dev/null || true
if ! command -v g++-14 >/dev/null; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq software-properties-common
  sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc-14 g++-14 build-essential pipx git libclang-dev
fi
command -v meson >/dev/null || { pipx install meson; pipx install ninja; }
    git submodule update --init --recursive
    rm -rf third_party/pq_blind_signatures/vole/faest-cpp-tmp/build_debug
    bash scripts/build-pomfrit-deps.sh
    MAYO_LIB="\$HOME/${REMOTE_DIR}/third_party/pq_blind_signatures/mayo-c-sys/target/debug"
    VOLE_LIB="\$HOME/${REMOTE_DIR}/third_party/pq_blind_signatures/vole-mayo-sys/target/debug"
    export LD_LIBRARY_PATH="\$MAYO_LIB:\$VOLE_LIB\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
    export RUST_MIN_STACK=16777216
    cargo test --workspace
    cargo test -p eat-pass-core -p eat-pass-cli --features dev-sim
REMOTE_EOF
  echo "=== workspace tests OK (remote) ==="
  exit 0
fi

IMAGE="${EAT_PASS_TEST_IMAGE:-ubuntu:24.04}"
PLATFORM="${EAT_PASS_DOCKER_PLATFORM:-linux/amd64}"

if ! command -v docker >/dev/null; then
  echo "docker required, or set EAT_PASS_REMOTE=azureuser@attest.secure.build" >&2
  exit 1
fi

if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
  echo "note: Docker linux/amd64 on Apple Silicon may fail PoMFRIT AVX2 builds." >&2
  echo "      use: EAT_PASS_REMOTE=azureuser@attest.secure.build $0" >&2
fi

echo "=== eat-pass workspace tests (Docker $PLATFORM / $IMAGE) ==="
echo "repo: $ROOT"

docker run --rm --platform "$PLATFORM" \
  -v "$ROOT:/eat-pass" -w /eat-pass \
  -e DEBIAN_FRONTEND=noninteractive \
  "$IMAGE" bash -c '
    set -euo pipefail
    apt-get update -qq
    apt-get install -y -qq git curl build-essential gcc-14 g++-14 pipx ca-certificates
    pipx install meson ninja
    export PATH="/root/.local/bin:$PATH"
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
    git submodule update --init --recursive
    rm -rf third_party/pq_blind_signatures/mayo-c-sys/target
    rm -rf third_party/pq_blind_signatures/vole-mayo-sys/target
    rm -rf third_party/pq_blind_signatures/vole/faest-cpp-tmp/build_debug
    rm -rf third_party/pq_blind_signatures/vole/faest-cpp-tmp/build
    bash scripts/build-pomfrit-deps.sh
    export RUST_MIN_STACK=16777216
    cargo test --workspace
    cargo test -p eat-pass-core -p eat-pass-cli --features dev-sim
  '

echo "=== workspace tests OK (docker) ==="
