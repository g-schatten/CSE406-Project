1. Get a pcap
Easiest — use the built-in fetcher (grabs two known-good real captures):


cd path/to/Sec_Project
bash tools/fetch_samples.sh
This downloads fixtures/public/wpa-Induction.pcap (Wireshark's sample, SSID Coherer, passphrase Induction) and fixtures/public/wpa.cap (aircrack-ng's test capture, passphrase biscotte).

Or grab a different one yourself — any public sample WPA2 capture works, e.g.:


curl -fsSL -o my.pcap "https://raw.githubusercontent.com/aircrack-ng/aircrack-ng/master/test/wpa2.eapol.cap"
(That specific one has SSID Harkonen, passphrase 12345678 — or test-pmkid.pcap from the same folder, a PMKID-only capture with SSID WLAN-771698, passphrase SP-91862D361.) Stick to public sample captures or a network you own — never one you have no right to analyze.

2. Make a tiny wordlist
A plain text file, one candidate per line — must contain the real password for mic/pmkid to succeed:


printf "wrongpass\nInduction\nother\n" > wl.txt
3. Run an attack

# Attack 1 — MIC dictionary (needs a full 4-way handshake)
python3 -m wpacrack mic --pcap fixtures/public/wpa-Induction.pcap --wordlist wl.txt --ssid Coherer

# Attack 2 — PMKID dictionary (needs only an M1 frame with a PMKID)
python3 -m wpacrack pmkid --pcap fixtures/public/wpa.cap --wordlist wl.txt

# Attack 3 — mask/brute (candidates generated from a pattern instead of a wordlist)
python3 -m wpacrack mask --pcap fixtures/public/wpa2.eapol.cap --mask '?d?d?d?d?d?d?d?d' --ssid Harkonen --timebox 60

# Defense analyzer — is this network even offline-crackable?
python3 -m wpacrack analyze --pcap fixtures/public/wpa.cap
Notes:

--ssid is optional — it auto-detects from the capture's own beacon if present (as with wpa.cap). Pass it explicitly if the capture has no beacon or you get a wrong result.
A capture only supports the attacks its content allows: mic needs M1+M2 (or M2+M3); pmkid needs an M1 with a PMKID KDE. Running the wrong attack on a capture correctly reports N/A, not an error.
If the real password isn't in your wordlist/mask, you correctly get EXHAUSTED, not a false hit.
4. Run everything at once (self-test)

python3 -m wpacrack.sim                          # regenerate synthetic fixtures
python3 -m wpacrack report --fixtures fixtures   # runs all 3 attacks + defense, asserts expected results
One caveat from the cross-check
The pcap you fetch must be classic pcap format, not .pcapng. We found a real bug where pcapng's Enhanced Packet Block reads the wrong byte offset for packet length, silently corrupting/truncating packets — and pcapng is Wireshark's modern default save format, so a capture you download or save fresh from Wireshark today is likely to hit this. All the URLs above are classic .pcap, so you're safe following this guide as-is; just don't feed it a .pcapng file yet. Want me to fix that bug now so pcapng works too?