#!/usr/bin/env bash
# Build "SafeRun Approval.app" (menu bar only, no Dock icon) and install it
# into ~/Applications, or into the directory given as the first argument.
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install_dir="${1:-$HOME/Applications}"
app_name="SafeRun Approval.app"
build_app="$repo_dir/target/release/$app_name"

cargo build --manifest-path "$repo_dir/Cargo.toml" --release --bin saferun-approval

version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_dir/Cargo.toml" | head -n 1)"

rm -rf "$build_app"
mkdir -p "$build_app/Contents/MacOS"
cp "$repo_dir/target/release/saferun-approval" "$build_app/Contents/MacOS/saferun-approval"
cat > "$build_app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>saferun-approval</string>
    <key>CFBundleIdentifier</key>
    <string>com.github.cmlad.saferun-approval</string>
    <key>CFBundleName</key>
    <string>SafeRun Approval</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$version</string>
    <key>CFBundleVersion</key>
    <string>$version</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
PLIST

mkdir -p "$install_dir"
rm -rf "$install_dir/$app_name"
cp -R "$build_app" "$install_dir/$app_name"
echo "installed $install_dir/$app_name"
