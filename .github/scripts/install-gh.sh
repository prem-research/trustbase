#!/usr/bin/env bash
set -euo pipefail
version=2.102.0
sha256=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
destination="${RUNNER_TEMP:?}/trustbase-gh"
mkdir -p "$destination"
curl --fail --location --retry 3 \
  "https://github.com/cli/cli/releases/download/v${version}/gh_${version}_linux_amd64.tar.gz" \
  --output "$destination/gh.tar.gz"
printf '%s  %s\n' "$sha256" "$destination/gh.tar.gz" | sha256sum --check -
tar -xzf "$destination/gh.tar.gz" -C "$destination"
echo "$destination/gh_${version}_linux_amd64/bin" >> "${GITHUB_PATH:?}"
