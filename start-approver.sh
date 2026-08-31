#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

cargo build --manifest-path "$repo_dir/Cargo.toml" --bin saferun-approval
exec "$repo_dir/target/debug/saferun-approval" "$@"
