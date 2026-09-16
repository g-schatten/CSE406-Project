#!/usr/bin/env bash
# Fetch public WPA sample captures used as external correctness oracles.
# These are NOT committed (see .gitignore); they belong to their upstream projects.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p fixtures/public
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36'

echo "wpa-Induction.pcap (SSID Coherer, passphrase Induction)"
curl -fsSL -A "$UA" -o fixtures/public/wpa-Induction.pcap \
  "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/wpa-Induction.pcap"

echo "wpa.cap (aircrack-ng test; SSID from its own beacon, passphrase biscotte)"
curl -fsSL -A "$UA" -o fixtures/public/wpa.cap \
  "https://github.com/aircrack-ng/aircrack-ng/raw/master/test/wpa.cap"

echo "done -> fixtures/public/"
