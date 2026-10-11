#!/usr/bin/env sh
set -eu

repo="${MCP_WARDEN_REPO:-AncientiCe/mcp-warden}"
install_dir="${MCP_WARDEN_INSTALL_DIR:-$HOME/.local/bin}"
tmp_dir="$(mktemp -d)"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Linux) os_part="unknown-linux-gnu" ;;
    Darwin) os_part="apple-darwin" ;;
    *) echo "Unsupported OS: $os" >&2; exit 1 ;;
  esac
  case "$arch" in
    x86_64|amd64) arch_part="x86_64" ;;
    arm64|aarch64) arch_part="aarch64" ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
  esac
  printf '%s-%s' "$arch_part" "$os_part"
}

checksum_verify() {
  file="$1"
  checksum_file="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$file")" && sha256sum -c "$(basename "$checksum_file")")
  else
    (cd "$(dirname "$file")" && shasum -a 256 -c "$(basename "$checksum_file")")
  fi
}

target="$(detect_target)"

version_override="${MCP_WARDEN_VERSION:-}"
local_archive="${MCP_WARDEN_LOCAL_ARCHIVE:-}"

if [ "$version_override" = "local" ]; then
  if [ -z "$local_archive" ]; then
    echo "MCP_WARDEN_LOCAL_ARCHIVE is required when MCP_WARDEN_VERSION=local" >&2
    exit 1
  fi
  archive="$local_archive"
else
  if [ -n "$version_override" ]; then
    tag="$version_override"
  else
    tag="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  fi
  if [ -z "$tag" ]; then
    echo "Could not determine the latest mcp-warden release; set MCP_WARDEN_VERSION" >&2
    exit 1
  fi
  version="${tag#v}"
  asset="mcp-warden-$version-$target.tar.gz"
  archive="$tmp_dir/$asset"
  checksum="$tmp_dir/mcp-warden-$target.sha256"
  curl -fL "https://github.com/$repo/releases/download/$tag/$asset" -o "$archive"
  curl -fL "https://github.com/$repo/releases/download/$tag/mcp-warden-$target.sha256" -o "$checksum"
  checksum_verify "$archive" "$checksum"
fi

mkdir -p "$install_dir"
tar -xzf "$archive" -C "$tmp_dir"
binary="$(find "$tmp_dir" -type f -name mcp-warden | head -n 1)"
if [ -z "$binary" ]; then
  echo "Archive did not contain an mcp-warden binary" >&2
  exit 1
fi
cp "$binary" "$install_dir/mcp-warden"
chmod +x "$install_dir/mcp-warden"

case ":$PATH:" in
  *":$install_dir:"*) ;;
  *)
    echo "Add mcp-warden to PATH:"
    echo "  export PATH=\"$install_dir:\$PATH\""
    ;;
esac

echo "mcp-warden installed to $install_dir/mcp-warden"
echo "Next: mcp-warden wrap <path/to/mcp-config.json>"
echo "Or wrap one server: mcp-warden --server-id github -- github-mcp-server stdio"
