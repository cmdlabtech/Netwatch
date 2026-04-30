# NetWatch

AI-powered network monitor. Detects packet loss via ICMP ping, triggers automatic packet captures, and uses Claude or Grok to diagnose the root cause and suggest remediation.

Open your browser, configure everything in the GUI, and get plain-English analysis of exactly what went wrong on your network.

---

## Features

- **Continuous ping monitoring** — tracks loss % per target in a rolling window
- **Automatic packet capture** — triggers tshark/tcpdump the moment loss crosses your threshold
- **Pre-buffer capture** — always-on ring buffer captures the seconds *before* the outage is detected, so you never miss the start of an event
- **AI analysis** — sends the capture summary to Claude (Anthropic) or Grok (xAI) for root-cause analysis and remediation steps
- **Browser GUI** — full configuration, live status, event log, and pcap download from a local web interface
- **Cross-platform** — macOS, Windows, and Linux; pre-built binaries for macOS and Windows

---

## Quick Start

### Pre-built binaries (macOS / Windows)

| Platform | Download |
|---|---|
| macOS | [**netwatch** (latest)](https://github.com/cmdlabtech/Netwatch/releases/latest/download/netwatch) |
| Windows | [**netwatch-windows.exe** (latest)](https://github.com/cmdlabtech/Netwatch/releases/latest/download/netwatch-windows.exe) |

All releases: [github.com/cmdlabtech/Netwatch/releases](https://github.com/cmdlabtech/Netwatch/releases)

**macOS** — see the [macOS note](#macos-note-binary-not-app) below before running.

**Windows** — the `.exe` bundles tshark and the Npcap installer; no Wireshark install required. On first launch, right-click → **Run as administrator** so the bundled Npcap installer can complete (silent, one-time). After that, capture works without admin because Npcap is configured for non-admin access.

### Run from source

Requires Python 3.11+. Dependencies install automatically on first run.

```bash
python3 netwatch.py
```

The browser opens automatically at `http://127.0.0.1:8765`.

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.11+ | Only needed when running from source |
| tshark (Wireshark) | Bundled inside the Windows `.exe`. Required separately when running from source, or for the macOS binary (macOS/Linux can also use tcpdump) |
| Npcap | Bundled inside the Windows `.exe` and silently installed on first run. Not needed on macOS/Linux |
| Anthropic or xAI API key | Enter in the GUI — stored locally in `~/.netwatch.conf` |
| Admin / root privileges | Required on macOS/Linux. On Windows: needed once on first launch so Npcap can install (silent, with non-admin capture enabled); subsequent runs do not need admin |

### Installing tshark

- **macOS:** `brew install wireshark` or download from [wireshark.org](https://www.wireshark.org/)
- **Windows:** install [Wireshark](https://www.wireshark.org/) — tshark is included. To avoid needing to run as Administrator, uncheck "Restrict Npcap driver's access to Administrators only" during the Wireshark/Npcap install.
- **Linux:** `sudo apt install tshark` or `sudo dnf install wireshark-cli`

On macOS/Linux you can also grant your user BPF access so you don't need `sudo` every time:
```bash
# macOS (Wireshark installs this helper)
sudo /Library/Application\ Support/Wireshark/ChmodBPF/Install\ ChmodBPF.app/Contents/MacOS/Install\ ChmodBPF

# Linux (add yourself to the wireshark group)
sudo usermod -aG wireshark $USER   # then log out and back in
```

---

## Configuration

All settings are available in the browser GUI. They are saved to `~/.netwatch.conf`.

| Setting | Default | Description |
|---|---|---|
| Targets | `8.8.8.8`, `1.1.1.1` | Hosts to ping |
| Interface | `en0` / `Ethernet` / `eth0` | Capture network interface |
| Egress interface | *(OS default)* | Interface used for AI API calls (useful if your LAN and WAN are on separate interfaces) |
| Ping interval | 1 s | How often to ping each target |
| Loss threshold | 20% | Loss % that triggers a capture |
| Window size | 10 pings | Rolling window for loss calculation |
| Capture duration | 30 s | How long to capture after a trigger |
| Cooldown | 120 s | Minimum time between captures for the same event |
| Pre-buffer | 10 s | Seconds of always-on ring buffer prepended to each capture |
| AI provider | Anthropic | Choose between Claude (Anthropic) or Grok (xAI) |
| Claude model | `claude-opus-4-5` | Any Anthropic model slug |
| Grok model | `grok-3-mini` | Any xAI model slug |

---

## macOS Note: Binary, Not .app

The macOS release is a plain Unix executable, not a `.app` bundle. This is intentional.

A `.app` bundle requires Apple code-signing and notarization to pass Gatekeeper without prompts. Distributing an unsigned `.app` means users must navigate to **System Settings → Privacy & Security** and click "Open Anyway" — a clunky and confusing flow. A raw binary avoids that dialog entirely when launched from the terminal.

**First run after downloading:**

macOS quarantines files downloaded from the internet. Remove the quarantine flag before running:

```bash
xattr -d com.apple.quarantine ./netwatch
chmod +x ./netwatch
sudo ./netwatch          # sudo needed for packet capture
```

Or right-click → **Open** in Finder, which also clears the quarantine flag.

---

## Build from Source

### macOS / Linux

```bash
pip install pyinstaller anthropic flask
pyinstaller --onefile --name netwatch --icon icon.icns --strip --clean netwatch.py
# output: dist/netwatch
```

### Windows

The Windows build bundles tshark + DLLs and the Npcap redistributable installer so end users do not need Wireshark.

Prerequisites on the build machine:
1. Install [Wireshark](https://www.wireshark.org/) — `build.bat` harvests `tshark.exe` and its DLLs from `C:\Program Files\Wireshark`.
2. Download the [Npcap installer](https://npcap.com/#download) and save it to `tools\npcap-installer.exe` (relative to the repo root).

Then:

```batch
build.bat
# output: dist\netwatch.exe
```

Both `tools\wireshark\` and `tools\npcap-installer.exe` are gitignored — they live only on the build machine.

---

## How It Works

1. **Ping loop** — NetWatch pings each target every second and records the result in a per-target rolling window.
2. **Loss detection** — when loss in the window crosses the threshold, a capture is triggered.
3. **Pre-buffer freeze** — the always-on ring buffer is frozen and prepended to the capture so the packets that *preceded* the outage are included.
4. **Capture** — tshark or tcpdump records traffic on the configured interface for the capture duration.
5. **AI analysis** — the capture summary is sent to Claude or Grok with a structured prompt asking for root-cause analysis and remediation steps.
6. **Results** — the analysis appears in the browser GUI and the raw pcap is available for download.

---

## License

MIT
