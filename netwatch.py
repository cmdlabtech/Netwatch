#!/usr/bin/env python3
"""
NetWatch — browser-controlled AI network monitor
==================================================
Run this file, your browser opens, configure everything in the GUI:
  - Anthropic API key
  - Targets, interface, thresholds, capture settings, Claude model
  - Start/stop monitoring
  - Download captured pcap files

Quickstart:
    python3 netwatch.py      # installs deps automatically on first run
    # browser opens at http://127.0.0.1:8765

Optional system dep: tshark (Wireshark) on PATH for packet capture.
On macOS/Linux tcpdump also works. On Windows the pre-built .exe bundles
tshark and the Npcap installer — first launch as Administrator installs
Npcap silently; subsequent launches need no extra setup.
"""

from __future__ import annotations

__version__ = "1.0.1"

import configparser
import json
import logging
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

try:
    import anthropic
    from flask import Flask, abort, jsonify, request, send_file
except ImportError:
    import subprocess as _sp, os as _os
    print("[netwatch] First run — installing required packages…", flush=True)
    _sp.check_call([sys.executable, "-m", "pip", "install", "anthropic", "flask"])
    _os.execv(sys.executable, [sys.executable] + sys.argv)


# Mutable container so the heartbeat route and watchdog thread share state.
_heartbeat_time: list[float | None] = [None]

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG STORE  — persists settings + API key to ~/.netwatch.conf
# ═══════════════════════════════════════════════════════════════════════════════

_CONFIG_PATH = Path.home() / ".netwatch.conf"

_DEFAULT_INTERFACE = (
    "en0" if sys.platform == "darwin"
    else "Ethernet" if sys.platform == "win32"
    else "eth0"
)


@dataclass
class Config:
    """All runtime tunables. Loaded from ~/.netwatch.conf, edited via web UI."""

    targets: list[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    interface: str = _DEFAULT_INTERFACE       # capture interface (tshark/tcpdump)
    egress_interface: str = ""               # outbound interface for LLM API calls ("" = OS default)
    ping_interval: float = 1.0
    loss_threshold: int = 20
    window_size: int = 10
    capture_duration: int = 30
    capture_dir: str = "./captures"
    cooldown_secs: int = 120
    claude_model: str = "claude-opus-4-7"
    prebuffer_secs: int = 10
    prebuffer_enabled: bool = True
    ai_provider: str = "anthropic"
    grok_model: str = "grok-3-mini"
    ai_enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "targets": self.targets,
            "interface": self.interface,
            "egress_interface": self.egress_interface,
            "ping_interval": self.ping_interval,
            "loss_threshold": self.loss_threshold,
            "window_size": self.window_size,
            "capture_duration": self.capture_duration,
            "capture_dir": self.capture_dir,
            "cooldown_secs": self.cooldown_secs,
            "claude_model": self.claude_model,
            "prebuffer_secs": self.prebuffer_secs,
            "prebuffer_enabled": self.prebuffer_enabled,
            "ai_provider": self.ai_provider,
            "grok_model": self.grok_model,
            "ai_enabled": self.ai_enabled,
        }


def load_config() -> Config:
    """Load config from disk, falling back to defaults for missing fields."""
    cfg = Config()
    if not _CONFIG_PATH.exists():
        return cfg
    parser = configparser.ConfigParser()
    parser.read(_CONFIG_PATH)
    if "config" not in parser:
        return cfg
    s = parser["config"]
    cfg.targets = [t.strip() for t in s.get("targets", "8.8.8.8,1.1.1.1").split(",") if t.strip()]
    cfg.interface = s.get("interface", cfg.interface)
    cfg.egress_interface = s.get("egress_interface", cfg.egress_interface)
    cfg.ping_interval = float(s.get("ping_interval", cfg.ping_interval))
    cfg.loss_threshold = int(s.get("loss_threshold", cfg.loss_threshold))
    cfg.window_size = int(s.get("window_size", cfg.window_size))
    cfg.capture_duration = int(s.get("capture_duration", cfg.capture_duration))
    cfg.capture_dir = s.get("capture_dir", cfg.capture_dir)
    cfg.cooldown_secs = int(s.get("cooldown_secs", cfg.cooldown_secs))
    cfg.claude_model = s.get("claude_model", cfg.claude_model)
    cfg.prebuffer_secs = int(s.get("prebuffer_secs", cfg.prebuffer_secs))
    cfg.prebuffer_enabled = s.getboolean("prebuffer_enabled", cfg.prebuffer_enabled)
    cfg.ai_provider = s.get("ai_provider", cfg.ai_provider)
    cfg.grok_model = s.get("grok_model", cfg.grok_model)
    cfg.ai_enabled = s.getboolean("ai_enabled", cfg.ai_enabled)
    return cfg


def save_config(cfg: Config) -> None:
    """Persist Config to ~/.netwatch.conf (preserving any existing api_key)."""
    parser = configparser.ConfigParser()
    if _CONFIG_PATH.exists():
        parser.read(_CONFIG_PATH)
    parser["config"] = {
        "targets": ",".join(cfg.targets),
        "interface": cfg.interface,
        "egress_interface": cfg.egress_interface,
        "ping_interval": str(cfg.ping_interval),
        "loss_threshold": str(cfg.loss_threshold),
        "window_size": str(cfg.window_size),
        "capture_duration": str(cfg.capture_duration),
        "capture_dir": cfg.capture_dir,
        "cooldown_secs": str(cfg.cooldown_secs),
        "claude_model": cfg.claude_model,
        "prebuffer_secs": str(cfg.prebuffer_secs),
        "prebuffer_enabled": str(cfg.prebuffer_enabled),
        "ai_provider": cfg.ai_provider,
        "grok_model": cfg.grok_model,
        "ai_enabled": str(cfg.ai_enabled),
    }
    with open(_CONFIG_PATH, "w") as f:
        parser.write(f)
    if sys.platform != "win32":
        _CONFIG_PATH.chmod(0o600)


def load_api_key() -> str | None:
    """Read saved Anthropic API key, if any."""
    if not _CONFIG_PATH.exists():
        return None
    parser = configparser.ConfigParser()
    parser.read(_CONFIG_PATH)
    return parser.get("auth", "api_key", fallback=None) or None


def save_api_key(key: str) -> None:
    """Save Anthropic API key to ~/.netwatch.conf (chmod 600)."""
    parser = configparser.ConfigParser()
    if _CONFIG_PATH.exists():
        parser.read(_CONFIG_PATH)
    parser["auth"] = {"api_key": key}
    with open(_CONFIG_PATH, "w") as f:
        parser.write(f)
    if sys.platform != "win32":
        _CONFIG_PATH.chmod(0o600)


def load_grok_api_key() -> str | None:
    """Read saved xAI Grok API key, if any."""
    if not _CONFIG_PATH.exists():
        return None
    parser = configparser.ConfigParser()
    parser.read(_CONFIG_PATH)
    return parser.get("grok", "api_key", fallback=None) or None


def save_grok_api_key(key: str) -> None:
    """Save xAI Grok API key to ~/.netwatch.conf (chmod 600)."""
    parser = configparser.ConfigParser()
    if _CONFIG_PATH.exists():
        parser.read(_CONFIG_PATH)
    parser["grok"] = {"api_key": key}
    with open(_CONFIG_PATH, "w") as f:
        parser.write(f)
    if sys.platform != "win32":
        _CONFIG_PATH.chmod(0o600)


def get_interface_ip(iface: str) -> str | None:
    """Return the first IPv4 address bound to *iface*, or None on failure."""
    if not iface:
        return None
    import re as _re
    if sys.platform == "win32":
        # `netsh interface ip show address` gives per-interface IP info
        try:
            out = subprocess.check_output(
                ["netsh", "interface", "ip", "show", "address", iface],
                text=True, stderr=subprocess.DEVNULL,
            )
            m = _re.search(r"IP Address[:\s]+(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
    elif sys.platform == "darwin":
        try:
            out = subprocess.check_output(
                ["ipconfig", "getifaddr", iface], text=True, stderr=subprocess.DEVNULL
            ).strip()
            if out:
                return out
        except Exception:
            pass
    else:
        try:
            out = subprocess.check_output(
                ["ip", "-4", "addr", "show", iface], text=True, stderr=subprocess.DEVNULL
            )
            m = _re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# MONITOR  — ping + rolling loss windows
# ═══════════════════════════════════════════════════════════════════════════════

class PingWindow:
    """Thread-safe rolling window of ping results."""

    def __init__(self, maxlen: int = 10) -> None:
        self._dq: deque[bool] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def record(self, success: bool) -> None:
        with self._lock:
            self._dq.append(success)

    def loss_pct(self) -> float:
        with self._lock:
            if not self._dq:
                return 0.0
            return sum(1 for r in self._dq if not r) / len(self._dq) * 100.0

    def snapshot(self) -> list[bool]:
        with self._lock:
            return list(self._dq)


class PingMonitor:
    """Manages PingWindows for all configured targets."""

    def __init__(self, targets: list[str], window_size: int = 10) -> None:
        self.targets = targets
        self.windows = {t: PingWindow(window_size) for t in targets}

    def ping(self, host: str, timeout_ms: int = 1000) -> bool:
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        elif sys.platform == "darwin":
            cmd = ["ping", "-c", "1", "-W", str(timeout_ms), host]
        else:
            cmd = ["ping", "-c", "1", "-w", str(max(1, timeout_ms // 1000)), host]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 2)
            return r.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def record(self, host: str, success: bool) -> None:
        self.windows[host].record(success)

    def loss_pct(self, host: str) -> float:
        return self.windows[host].loss_pct()

    def snapshot_all(self) -> dict[str, float]:
        return {t: self.windows[t].loss_pct() for t in self.targets}


# ═══════════════════════════════════════════════════════════════════════════════
# CAPTURE  — tshark/tcpdump + always-on ring buffer
# ═══════════════════════════════════════════════════════════════════════════════

def _bundled_resource_dir() -> Path:
    """Directory containing bundled resources (tshark, npcap installer).

    When frozen by PyInstaller --onefile, resources are extracted to sys._MEIPASS.
    When running from source, resources live next to this script.
    """
    base = getattr(sys, "_MEIPASS", None)
    return Path(base) if base else Path(__file__).resolve().parent


def _bundled_wireshark_dir() -> Path | None:
    d = _bundled_resource_dir() / "tools" / "wireshark"
    return d if (d / ("tshark.exe" if sys.platform == "win32" else "tshark")).exists() else None


def _is_admin_windows() -> bool:
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _npcap_installed() -> bool:
    """Detect Npcap on Windows. Checks the service first, then wpcap.dll."""
    if sys.platform != "win32":
        return True
    try:
        r = subprocess.run(["sc", "query", "npcap"], capture_output=True, timeout=5)
        if r.returncode == 0 and b"STATE" in r.stdout:
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    sysroot = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    for candidate in (sysroot / "System32" / "Npcap" / "wpcap.dll",
                      sysroot / "System32" / "wpcap.dll"):
        if candidate.exists():
            return True
    return False


def _run_with_heartbeat(cmd: list[str], label: str, timeout: int) -> int:
    """Run a child process while printing a dot every 2 s so the console doesn't look frozen."""
    print(f"  [*] {label} ", end="", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    waited = 0
    try:
        while True:
            try:
                rc = proc.wait(timeout=2)
                print(" done.", flush=True)
                return rc
            except subprocess.TimeoutExpired:
                print(".", end="", flush=True)
                waited += 2
                if waited >= timeout:
                    proc.kill()
                    print(" timed out.", flush=True)
                    return -1
    except KeyboardInterrupt:
        proc.kill()
        raise


def ensure_npcap_windows() -> None:
    """Install bundled Npcap if missing. No-op on non-Windows or when already installed."""
    if sys.platform != "win32":
        return
    if _npcap_installed():
        print("  [ok] Npcap driver already installed.", flush=True)
        return
    installer = _bundled_resource_dir() / "tools" / "npcap-installer.exe"
    if not installer.exists():
        print("  [!!] Npcap is not installed and no bundled installer was found.", flush=True)
        print("       Install Npcap from https://npcap.com/ to enable packet capture.", flush=True)
        return
    print("  [..] Npcap not detected — running first-time installer (silent).", flush=True)
    if not _is_admin_windows():
        print("       This needs Administrator rights — Windows will show a UAC prompt.", flush=True)
    args = ["/S", "/winpcap_mode=yes", "/admin_only=no",
            "/loopback_support=yes", "/dlt_null=yes"]
    if _is_admin_windows():
        rc = _run_with_heartbeat([str(installer)] + args,
                                 "Installing Npcap (no admin prompt, already elevated)",
                                 timeout=300)
    else:
        ps = (
            f"Start-Process -FilePath '{installer}' "
            f"-ArgumentList '{' '.join(args)}' -Verb RunAs -Wait"
        )
        rc = _run_with_heartbeat(
            ["powershell", "-NoProfile", "-Command", ps],
            "Waiting for Npcap installer (approve the UAC prompt)",
            timeout=600,
        )
    if rc == 0 and _npcap_installed():
        print("  [ok] Npcap installed successfully.", flush=True)
    else:
        print("  [!!] Npcap install did not complete — capture will not work until it is installed.",
              flush=True)


def detect_capture_tool() -> str:
    # 1. Bundled tshark (shipped inside the PyInstaller exe). Highest priority so
    #    a user with a partial/old Wireshark install still gets the version we tested with.
    bundled = _bundled_wireshark_dir()
    if bundled is not None:
        os.environ["PATH"] = str(bundled) + os.pathsep + os.environ.get("PATH", "")

    # 2. On Windows, also probe common Wireshark install locations as a fallback.
    if sys.platform == "win32":
        _wireshark_dirs = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark",
        ]
        for d in _wireshark_dirs:
            if (d / "tshark.exe").exists():
                os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + str(d)
                break

    tools = ["tshark"] if sys.platform == "win32" else ["tshark", "tcpdump"]
    for tool in tools:
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=5)
            return tool
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    if sys.platform == "win32":
        raise RuntimeError(
            "tshark not found. The pre-built netwatch.exe ships tshark internally — "
            "if you're running from source, install Wireshark from wireshark.org."
        )
    raise RuntimeError("Neither tshark nor tcpdump found. Install wireshark or tcpdump.")


def run_capture(interface: str, duration: int, pcap_path: str, tool: str, host_filter: str = "") -> None:
    if tool == "tshark":
        cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", pcap_path]
        if host_filter:
            cmd += ["-f", f"host {host_filter}"]
    else:
        cmd = ["tcpdump", "-i", interface, "-G", str(duration), "-W", "1", "-w", pcap_path]
        if host_filter:
            cmd += [f"host {host_filter}"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=duration + 15)
    except PermissionError as exc:
        if sys.platform == "win32":
            raise PermissionError(f"{tool} needs Administrator privileges.") from exc
        raise PermissionError(f"{tool} needs elevated privileges. Try: sudo python3 netwatch.py") from exc

    stderr = r.stderr.decode(errors="replace").strip()
    pcap = Path(pcap_path)
    wrote_file = pcap.exists() and pcap.stat().st_size > 0

    # tshark sometimes exits 1 on normal completion; tcpdump exit 1 is a real error.
    # Either way, the source of truth is whether a non-empty pcap file was written.
    if not wrote_file:
        msg = stderr or f"(no stderr; exit {r.returncode})"
        lower = stderr.lower()
        if "permission" in lower or "operation not permitted" in lower or "you don't have" in lower:
            hint = (
                "Run with `sudo python3 netwatch.py` (macOS/Linux), or install Wireshark "
                "and run its ChmodBPF helper to grant your user BPF access."
                if sys.platform != "win32"
                else "Run this script as Administrator."
            )
            raise PermissionError(f"{tool} cannot capture on {interface} — {msg}. {hint}")
        raise RuntimeError(f"{tool} produced no pcap (exit {r.returncode}): {msg}")


def get_capture_summary(pcap_path: str) -> str:
    if not Path(pcap_path).exists():
        return "(pcap file not found)"
    try:
        r = subprocess.run(
            ["tshark", "-r", pcap_path, "-z", "io,stat,0", "-q"],
            capture_output=True, timeout=30,
        )
        lines = r.stdout.decode(errors="replace").strip().splitlines()
        if len(lines) > 50:
            lines = lines[:50] + [f"... ({len(lines) - 50} lines truncated)"]
        return "\n".join(lines) or "(no output from tshark)"
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return f"(summary unavailable: {exc})"


def _merge_pcaps(inputs: list[str], output: str) -> None:
    existing = [f for f in inputs if Path(f).exists()]
    if not existing:
        return
    try:
        subprocess.run(["mergecap", "-w", output] + existing, capture_output=True, timeout=30)
    except FileNotFoundError:
        print("[netwatch] mergecap not found — prebuffer will not be prepended to capture. Install Wireshark to enable this.", flush=True)
    except subprocess.TimeoutExpired:
        pass


class RingBufferCapture:
    """Always-on tshark ring buffer keeping the last N seconds of traffic."""

    def __init__(self, interface: str, capture_dir: str, prebuffer_secs: int = 10, tag: str = "pre") -> None:
        self.interface = interface
        self.capture_dir = capture_dir
        self.prebuffer_secs = prebuffer_secs
        self.tag = tag
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @property
    def ring_pattern(self) -> str:
        return str(Path(self.capture_dir) / f"{self.tag}_ring.pcap")

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="ring-capture")
        self._thread.start()

    def _run(self) -> None:
        cmd = [
            "tshark", "-i", self.interface,
            "-b", f"duration:{self.prebuffer_secs}",
            "-b", "files:3",
            "-w", self.ring_pattern,
        ]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._stop_event.wait()
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        except (FileNotFoundError, PermissionError):
            pass

    def freeze(self) -> list[str]:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=8)
        return sorted(str(p) for p in Path(self.capture_dir).glob(f"{self.tag}_ring*.pcap"))

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=8)
        for f in Path(self.capture_dir).glob(f"{self.tag}_ring*.pcap"):
            try:
                f.unlink()
            except OSError:
                pass


class CaptureManager:
    """Optional ring-buffer pre-capture + on-demand outage capture."""

    def __init__(self, interface: str, capture_dir: str, capture_duration: int,
                 prebuffer_enabled: bool = True, prebuffer_secs: int = 10) -> None:
        self.interface = interface
        self.capture_dir = capture_dir
        self.capture_duration = capture_duration
        self.tool = detect_capture_tool()
        self._ring: RingBufferCapture | None = None
        self._prebuffer_secs = prebuffer_secs
        self._ring_lock = threading.Lock()
        if prebuffer_enabled and self.tool == "tshark":
            self._ring = RingBufferCapture(interface, capture_dir, prebuffer_secs)

    def start_prebuffer(self) -> None:
        if self._ring:
            self._ring.start()

    def trigger(self, label: str, host_filter: str = "") -> tuple[str, str]:
        ts = time.strftime("%Y%m%d_%H%M%S")
        pcap_path = str(Path(self.capture_dir) / f"capture_{label}_{ts}.pcap")

        pre_files: list[str] = []
        with self._ring_lock:
            if self._ring:
                pre_files = self._ring.freeze()
                self._ring = RingBufferCapture(self.interface, self.capture_dir, self._prebuffer_secs)
                self._ring.start()

        run_capture(self.interface, self.capture_duration, pcap_path, self.tool, host_filter)

        if pre_files and self.tool == "tshark":
            merged = pcap_path.replace(".pcap", "_merged.pcap")
            _merge_pcaps(pre_files + [pcap_path], merged)
            if Path(merged).exists():
                Path(pcap_path).unlink(missing_ok=True)
                Path(merged).rename(pcap_path)
            for f in pre_files:
                Path(f).unlink(missing_ok=True)

        return pcap_path, get_capture_summary(pcap_path)

    def stop(self) -> None:
        if self._ring:
            self._ring.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYZER  — Claude API
# ═══════════════════════════════════════════════════════════════════════════════

class ClaudeAnalyzer:
    """Sends a structured prompt to Claude for root-cause analysis."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def _make_anthropic_client(self) -> "anthropic.Anthropic":
        import httpx
        ip = get_interface_ip(self.config.egress_interface)
        if ip:
            transport = httpx.HTTPTransport(local_address=ip)
            http_client = httpx.Client(transport=transport)
            return anthropic.Anthropic(http_client=http_client)
        return anthropic.Anthropic()

    def analyze(self, targets: list[str], loss: dict[str, float], summary: str, pcap_path: str) -> str:
        prompt = self._build_prompt(targets, loss, summary, pcap_path)
        if self.config.ai_provider == "grok":
            return self._invoke_grok(prompt)
        try:
            return self._invoke_anthropic(prompt)
        except anthropic.RateLimitError:
            time.sleep(60)
            return self._invoke_anthropic(prompt)

    def _build_prompt(self, targets: list[str], loss: dict[str, float], summary: str, pcap_path: str) -> str:
        loss_lines = "\n".join(f"- {h}: {l:.1f}% packet loss" for h, l in loss.items())
        return f"""You are an expert network engineer and packet analysis specialist.

Analyze the following packet capture summary from a network target that went offline and triggered an automatic packet capture. The capture was started by the monitoring app after the target was offline for a configured period of time.

**Affected Target(s):** {", ".join(targets)}
**Packet Loss at Trigger:** {loss_lines}
**Capture File:** `{pcap_path}` (filtered to traffic involving the affected target)

**Packet Capture Summary:**
```
{summary}
```

**Core Principles:**
- Always troubleshoot systematically using the OSI model (Layer 1 → Layer 7).
- Be conservative, evidence-based, and realistic. Simple physical link flaps, cable disconnects, or interface issues are the most common causes of brief outages.
- Do not hallucinate or over-diagnose storms, loops, or attacks unless the data clearly supports it.
- Normal reconnection behavior (extra ARP, DHCP renewals, TCP retransmissions, duplicate frames during recovery) is expected and usually benign.

**OSI-Based Analysis Order:**
- Layer 1 (Physical): Link up/down events, interface flaps, cable issues
- Layer 2 (Data Link): ARP behavior, MAC flapping, broadcast/multicast storms, switching loops
- Layer 3 (Network): IP routing, ICMP, DHCP requests/renewals
- Layer 4+ (Transport & above): TCP/UDP retransmissions, session recovery, resets

**Structure your response exactly like this:**

**1. Capture Overview**
- Duration of capture:
- Total packets:
- Approximate outage window (based on traffic patterns):
- Top 5 protocols by volume:
- Top 5 talkers (src/dest) by packet count:

**2. OSI Layer Analysis**
- Layer 1 (Physical):
- Layer 2 (Data Link):
- Layer 3 (Network):
- Layer 4+ (Transport & higher):

**3. Key Findings**
List only real issues with clear evidence (timestamps, packet counts, MAC/IP). Use severity: Critical / High / Medium / Low / Normal Behavior

**4. Root Cause Conclusion**
Most likely explanation (be realistic — "simple link flap / cable disconnect" is a valid and common answer).

**5. Recommendations**
- Immediate actions
- Long-term prevention (if needed)

Be professional, concise, and non-alarmist. Prefer the simplest explanation that fits the evidence.
"""

    def _invoke_anthropic(self, prompt: str) -> str:
        client = self._make_anthropic_client()
        response = client.messages.create(
            model=self.config.claude_model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def _invoke_grok(self, prompt: str) -> str:
        import httpx
        key = os.environ.get("GROK_API_KEY", "")
        if not key:
            raise RuntimeError("Grok API key not set — add it in Settings")
        payload = {
            "model": self.config.grok_model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024,
        }
        ip = get_interface_ip(self.config.egress_interface)
        transport = httpx.HTTPTransport(local_address=ip) if ip else None
        with httpx.Client(transport=transport, timeout=120) as client:
            resp = client.post(
                "https://api.x.ai/v1/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {key}"},
            )
        if resp.status_code != 200:
            raise RuntimeError(f"Grok API error {resp.status_code}: {resp.text}")
        return resp.json()["choices"][0]["message"]["content"]


# ═══════════════════════════════════════════════════════════════════════════════
# WEB STATE  — thread-safe state shared between NetWatch and the HTTP API
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class WebState:
    """Live state consumed by /api/status."""

    targets: list[str]
    interface: str
    capture_duration: int
    cooldown_secs: int
    tool: str = ""
    window_snaps: dict[str, list[bool]] = field(default_factory=dict)
    loss_pct: dict[str, float] = field(default_factory=dict)
    events: deque = field(default_factory=lambda: deque(maxlen=200))
    analyses: deque = field(default_factory=lambda: deque(maxlen=20))
    capturing: dict[str, float] = field(default_factory=dict)
    analyzing: set = field(default_factory=set)
    last_cap_time: dict[str, float] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def __post_init__(self) -> None:
        for t in self.targets:
            self.window_snaps.setdefault(t, [])
            self.loss_pct.setdefault(t, 0.0)

    def add_event(self, level: str, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.events.appendleft((ts, level.upper(), msg))

    def update_target(self, host: str, snap: list[bool], loss: float) -> None:
        with self._lock:
            self.window_snaps[host] = snap
            self.loss_pct[host] = loss

    def set_analysis(self, text: str, target: str = "") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        entry = {"id": f"{target}-{ts}", "target": target, "time": ts, "text": text}
        with self._lock:
            self.analyses.appendleft(entry)

    def clear(self) -> None:
        """Reset ping history, analyses, and event log without stopping the monitor."""
        with self._lock:
            for t in self.targets:
                self.window_snaps[t] = []
                self.loss_pct[t] = 0.0
            self.events.clear()
            self.analyses.clear()

    def set_capturing(self, target: str, active: bool) -> None:
        with self._lock:
            now = time.time()
            if active:
                self.capturing[target] = now
                self.last_cap_time[target] = now
            else:
                self.capturing.pop(target, None)

    def set_analyzing(self, target: str, active: bool) -> None:
        with self._lock:
            if active:
                self.analyzing.add(target)
            else:
                self.analyzing.discard(target)

    def snapshot(self) -> dict:
        with self._lock:
            uptime_s = int(time.time() - self.start_time)
            h, rem = divmod(uptime_s, 3600)
            m, s = divmod(rem, 60)
            now = time.time()
            capturing_targets = [
                {
                    "target": t,
                    "elapsed": now - started,
                    "duration": self.capture_duration,
                }
                for t, started in self.capturing.items()
            ]
            cooldowns = [
                max(0.0, self.cooldown_secs - (now - lct))
                for lct in self.last_cap_time.values()
            ]
            cooldown_remaining = max(cooldowns) if cooldowns else 0
            return {
                "targets": list(self.targets),
                "interface": self.interface,
                "tool": self.tool,
                "uptime": f"{h:02d}:{m:02d}:{s:02d}",
                "window_snaps": dict(self.window_snaps),
                "loss_pct": dict(self.loss_pct),
                "events": list(self.events),
                "analyses": list(self.analyses),
                "capturing_targets": capturing_targets,
                "analyzing_targets": list(self.analyzing),
                "capture_duration": self.capture_duration,
                "cooldown_remaining": cooldown_remaining,
            }


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class NetWatch:
    """Wires together monitor + capture + analyzer; updates a WebState."""

    def __init__(self, config: Config, state: WebState) -> None:
        self.config = config
        self.state = state
        self.monitor = PingMonitor(config.targets, config.window_size)
        self.capture = CaptureManager(
            config.interface, config.capture_dir, config.capture_duration,
            config.prebuffer_enabled, config.prebuffer_secs,
        )
        state.tool = self.capture.tool
        self.analyzer = ClaudeAnalyzer(config)
        self._running = False
        self._capturing_lock = threading.Lock()
        self._capturing: set[str] = set()
        self._last_cap: dict[str, float] = {}

    def run(self) -> None:
        self._running = True
        os.makedirs(self.config.capture_dir, exist_ok=True)
        try:
            self.capture.start_prebuffer()
        except Exception as exc:
            self.state.add_event("WARN", f"Pre-buffer disabled: {exc}")

        self.state.add_event("INFO", f"Monitoring: {', '.join(self.config.targets)}")
        self.state.add_event("INFO", f"Interface: {self.config.interface} • Threshold: {self.config.loss_threshold}%")

        while self._running:
            for target in self.config.targets:
                if not self._running:
                    break
                success = self.monitor.ping(target)
                self.monitor.record(target, success)
                snap = self.monitor.windows[target].snapshot()
                loss = self.monitor.loss_pct(target)
                self.state.update_target(target, snap, loss)
                if loss >= self.config.loss_threshold:
                    self._maybe_trigger(target, loss)
            time.sleep(self.config.ping_interval)

    def _maybe_trigger(self, target: str, loss: float) -> None:
        now = time.time()
        with self._capturing_lock:
            if target in self._capturing:
                return
            if (now - self._last_cap.get(target, 0.0)) < self.config.cooldown_secs:
                return
            self._capturing.add(target)
            self._last_cap[target] = now
        self.state.set_capturing(target, True)
        threading.Thread(target=self._capture_and_analyze, args=(target, loss), daemon=True).start()

    def _capture_and_analyze(self, target: str, loss: float) -> None:
        self.state.add_event("CAPTURE", f"{target} at {loss:.1f}% loss — {self.config.capture_duration}s capture started")
        try:
            label = target.replace(".", "_").replace(":", "_")
            pcap_path, summary = self.capture.trigger(label=label, host_filter=target)
            # Pcap is written — clear the progress bar before the (potentially slow) API call
            self.state.set_capturing(target, False)
            self.state.add_event("CAPTURE", f"Saved: {Path(pcap_path).name}")
            if self.config.ai_enabled:
                self.state.add_event("ANALYSIS", f"Sending {target} capture to Claude…")
                self.state.set_analyzing(target, True)
                try:
                    analysis = self.analyzer.analyze([target], {target: loss}, summary, pcap_path)
                finally:
                    self.state.set_analyzing(target, False)
                self.state.set_analysis(analysis, target=target)
                self.state.add_event("ANALYSIS", f"Analysis complete for {target}")
        except Exception as exc:
            self.state.add_event("ERROR", f"Capture/analysis failed for {target}: {exc}")
        finally:
            with self._capturing_lock:
                self._capturing.discard(target)
            self.state.set_capturing(target, False)

    def stop(self) -> None:
        self._running = False
        self.capture.stop()
        with self._capturing_lock:
            for target in list(self._capturing):
                self.state.set_capturing(target, False)
        self.state.add_event("INFO", "Monitoring stopped")


# ═══════════════════════════════════════════════════════════════════════════════
# CONTROLLER  — singleton holding the active NetWatch + thread + state
# ═══════════════════════════════════════════════════════════════════════════════

class Controller:
    """Holds current config and the (optional) running NetWatch instance."""

    def __init__(self) -> None:
        self.config = load_config()
        save_config(self.config)  # ensure [config] section is always written on startup
        self.state: WebState | None = None
        self._netwatch: NetWatch | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        saved = load_api_key()
        if saved:
            os.environ["ANTHROPIC_API_KEY"] = saved
        saved_grok = load_grok_api_key()
        if saved_grok:
            os.environ["GROK_API_KEY"] = saved_grok

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> tuple[bool, str]:
        with self._lock:
            if self.running:
                return False, "Already running"
            if self.config.ai_enabled:
                if self.config.ai_provider == "grok" and not os.environ.get("GROK_API_KEY"):
                    return False, "Set your xAI Grok API key first (Settings → API Key)"
                if self.config.ai_provider != "grok" and not os.environ.get("ANTHROPIC_API_KEY"):
                    return False, "Set your Anthropic API key first (Settings → API Key)"
            try:
                self.state = WebState(
                    targets=list(self.config.targets),
                    interface=self.config.interface,
                    capture_duration=self.config.capture_duration,
                    cooldown_secs=self.config.cooldown_secs,
                )
                self._netwatch = NetWatch(self.config, self.state)
            except Exception as exc:
                return False, f"Failed to initialise: {exc}"
            self._thread = threading.Thread(target=self._netwatch.run, daemon=True, name="netwatch")
            self._thread.start()
            return True, "Started"

    def stop(self) -> tuple[bool, str]:
        with self._lock:
            if not self.running or self._netwatch is None:
                return False, "Not running"
            self._netwatch.stop()
            if self._thread:
                self._thread.join(timeout=5)
            self._thread = None
            return True, "Stopped"

    def update_config(self, data: dict) -> tuple[bool, str]:
        try:
            new = Config(**data)
        except TypeError as exc:
            return False, f"Bad config: {exc}"
        save_config(new)
        with self._lock:
            self.config = new
        return True, "Saved (restart monitoring to apply)"

    def get_state(self) -> dict:
        base = {
            "running": self.running,
            "interface": self.config.interface,
            "targets": list(self.config.targets),
            "tool": "",
            "uptime": "00:00:00",
            "window_snaps": {t: [] for t in self.config.targets},
            "loss_pct": {t: 0.0 for t in self.config.targets},
            "events": [],
            "analyses": [],
            "capturing_targets": [],
            "analyzing_targets": [],
            "capture_duration": self.config.capture_duration,
            "cooldown_remaining": 0,
        }
        if self.state is not None:
            base.update(self.state.snapshot())
            base["running"] = self.running
        base["captures"] = self._list_captures()
        return base

    def _list_captures(self) -> list[dict]:
        d = Path(self.config.capture_dir)
        if not d.exists():
            return []
        items = []
        for p in sorted(d.glob("*.pcap"), key=lambda x: x.stat().st_mtime, reverse=True):
            if p.name.startswith("pre_ring") or p.name.endswith("_merged.pcap"):
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            items.append({
                "name": p.name,
                "size": st.st_size,
                "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
        return items


# ═══════════════════════════════════════════════════════════════════════════════
# WEB SERVER  — Flask routes + embedded HTML
# ═══════════════════════════════════════════════════════════════════════════════

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAEg0lEQVR4nI1Xz28cNRT+7PHsJrshaZM0SZN2I1VIpFIFSKhS/6feuXFGHDlzQuLCnROiB1TEgRsXJI4cgqr8VlLazWZnXD3bz372zK4YaZOJ1+/5e9/74S9q//FTq6DQeawFlF+3oHf6U8HSOvx7YRDWydRCKd1xmb5T0V47z/7r9BrdeSty5kC6RdoUgIVNSsXdAhyv2fju97OtdR/DZ7sPbVDCSYySnTFXKdrkWOxh5hhhHlIGwmSeejLBYERGYG0JTGfR5gd3H/+992FQ0Jei6DMsI+lGl9KyFEO0McsOToF0D1iegkVAu4/meomkBmd9h3disBJQXpxtW9bAAgAIbRbqNBxOUVC79Bv1r3cLjvwsAsHgTWc1UNJnx85SEWaweoD4dVkXZR3p7KCYu9TDjNStaBobYnQsiHxROyU2EihDVOfRqm670NC4mwNNA0tFVhv/ofZsmr6jhA85mFL/cxpNRBSGTD5utfdQG+i9BzDrH0HdzdGenGF2corGWui1MbSpAhA5AfNAZN3IMW7gCi4hlEXj3poGevs+9IsvoJ8cYvj4AOO1MdSbU7z/9XdcvXqN2eUVzL0NkSsJxHtKTNCnjQDVweRpCJeMPRNZQigD1FPGoDp4iOrJBPrwEVaeHWHtk49RX17j6vsfcf7Tz1DDAXRt0DZtcVlxXaWZ779WHgC3oF/UPdOMUDTOh97bQbW7DbV1H3p3B6NPj7D+2TPM//gTx19/i/nNDfRoFWgoSmaD37uXltqfHIVVRpiuUW4bz5xyTLgoH2xDr69Bb21Ab26ieriLjeefo57OcPzVN7j9940HQcxl6bCdiam7VFExkSHnk4eG+Hs6RXvzFs3FNeYn55j/c4yLX37D28trbH35EvXOFuz0FtBVilSVaQgw9rkGIk0cvTdmAO4HzYHxCpSpoAcD2NEq1GgVejyC3liHHo1QH06AZo6b736A/e8d1MqQiqiTAmZWpRSUOaqignGIjQaGA6CqoLQC6to5twSmHqCig+raAdOTR7C2xfTVa9jTcw881hkPIV9zJp9aQpG4ftBQlUZba9iq8vpJAS2hv53Bvnvv2pRSTWs0oYkd9dffwOY9qIM9d7g9u+Cmy2ogCBKiR/crllAH6q4FZqkuVJzP/hpNrWthpyFlZ5ce7cowXC+yzZOuNAlV3qdxXrv8sR4UBGWSTbBH6XFPoH0+F4or0BQ1QwtDA9hfxnJKlSlhwVC2lEQkK7ZMp9hH17wQt1ra8iDKWQnUF7fk/3v4+k627sYRisnE/wkybRhKJuBIDJV93K8nl13LKUgPyliXF6+Ceh/nTxJlhYM+mxxkrg/TOTwATTokVaaMJL8XenJaiNJk38dOitwPIhs0oSiKZJzTKEUqDRm5zzfEMjVc+k3+TSkaZcF073WxL0qYMt+LbFMgPGGdKGVqSxp9rvzolE7iGM1SQPe/vMYXg+b/nDgFxkvwZJS0fmohVkxSVLrCDQXHMs79Fj3j7ftZjJrQH8y9z9dmDiDPEsuXfpEZp65jT4sLTaaHi1XjA2RIWr2VveTUAAAAAElFTkSuQmCC">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWatch</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
  body { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .markdown h1, .markdown h2, .markdown h3 { font-weight: 700; margin: 0.6em 0 0.2em; }
  .markdown h2 { font-size: 1rem; color: #67e8f9; }
  .markdown h3 { font-size: 0.9rem; color: #a5f3fc; }
  .markdown p { margin: 0.4em 0; }
  .markdown ol, .markdown ul { margin: 0.4em 0 0.4em 1.5em; }
  .markdown li { margin: 0.2em 0; }
  .markdown code { background: #0f172a; padding: 1px 5px; border-radius: 3px; font-size: 0.85em; }
  .markdown pre { background: #0f172a; padding: 8px; border-radius: 4px; overflow-x: auto; margin: 0.4em 0; }
  .markdown strong { color: #f1f5f9; }
</style>
</head>
<body class="bg-slate-950 text-slate-200 min-h-screen">
<div class="max-w-7xl mx-auto p-4 lg:p-6">

  <!-- Header -->
  <header class="flex flex-wrap justify-between items-center gap-3 mb-5">
    <h1 class="text-2xl font-bold flex items-center gap-3">
      <span id="statusDot" class="text-slate-600 text-3xl leading-none">●</span>
      NetWatch
      <span class="text-xs font-normal text-slate-500">browser-controlled network monitor</span>
    </h1>
    <div class="flex gap-2">
      <button id="toggleBtn" class="bg-emerald-600 hover:bg-emerald-500 px-5 py-2 rounded font-bold transition">Start</button>
      <button id="clearBtn" class="bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2 rounded transition">✕ Clear</button>
      <button id="settingsBtn" class="bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2 rounded transition">⚙ Settings</button>
    </div>
  </header>

  <!-- Status bar -->
  <div class="bg-slate-900 border border-slate-800 rounded-lg p-3 mb-4 grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
    <div><span class="text-slate-500">Interface:</span> <span id="interface" class="text-cyan-300">—</span></div>
    <div><span class="text-slate-500">Tool:</span> <span id="tool" class="text-cyan-300">—</span></div>
    <div><span class="text-slate-500">Uptime:</span> <span id="uptime">00:00:00</span></div>
    <div><span class="text-slate-500">Cooldown:</span> <span id="cooldown">—</span></div>
  </div>

  <!-- Targets + Analysis side by side -->
  <div class="grid lg:grid-cols-5 gap-4 mb-4">
    <!-- Targets -->
    <div class="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-4">
      <h2 class="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3">Targets</h2>
      <div id="targets" class="space-y-2"></div>
      <div id="captureStatus" class="hidden mt-4 p-3 bg-fuchsia-950/40 border border-fuchsia-800 rounded space-y-3"></div>
      <div id="analyzeStatus" class="hidden mt-2 p-3 bg-amber-950/40 border border-amber-800 rounded space-y-1"></div>
    </div>

    <!-- Analysis List -->
    <div class="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-lg p-4">
      <h2 class="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-3">Analysis</h2>
      <div id="analysisList">
        <p class="text-slate-500 italic text-sm">Waiting for first capture event…</p>
      </div>
    </div>
  </div>

  <!-- Event log -->
  <div class="bg-slate-900 border border-slate-800 rounded-lg p-4 mb-4">
    <h2 class="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3">Event Log</h2>
    <div id="events" class="space-y-1 text-xs max-h-64 overflow-y-auto"></div>
  </div>

  <!-- Captures -->
  <div class="bg-slate-900 border border-slate-800 rounded-lg p-4">
    <div class="flex justify-between items-center mb-3">
      <h2 class="text-xs font-bold uppercase tracking-wider text-slate-500">Captures</h2>
      <button id="refreshCapsBtn" class="text-xs text-slate-500 hover:text-slate-300">↻ refresh</button>
    </div>
    <div id="captures" class="space-y-1 text-sm"></div>
  </div>

</div>

<!-- Settings Modal -->
<div id="settingsModal" class="hidden fixed inset-0 bg-black/70 flex items-start justify-center z-50 p-4 overflow-y-auto">
  <div class="bg-slate-900 border border-slate-800 rounded-lg w-full max-w-2xl my-8">
    <div class="flex justify-between items-center p-5 border-b border-slate-800">
      <h2 class="text-xl font-bold">Settings</h2>
      <button id="closeSettings" class="text-slate-400 hover:text-white text-2xl leading-none">&times;</button>
    </div>
    <div class="p-5 space-y-5 text-sm">

      <!-- AI Analysis toggle -->
      <div class="flex items-center justify-between bg-slate-950 border border-slate-800 rounded px-4 py-3">
        <div>
          <span class="font-bold text-sm">AI Analysis</span>
          <p class="text-xs text-slate-500 mt-0.5">Automatically analyse packet captures with an AI model when loss is detected.</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer ml-4 shrink-0">
          <input type="checkbox" id="cfgAiEnabled" class="sr-only peer" onchange="toggleAiEnabled(this.checked)">
          <div class="w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:bg-cyan-600 transition after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:after:translate-x-full"></div>
        </label>
      </div>

      <!-- AI provider + key sections (hidden when AI is disabled) -->
      <div id="aiSettingsBlock">

      <!-- AI Provider visual selector -->
      <div>
        <label class="block mb-2 text-slate-400 text-sm">AI Provider — analysis will be sent exclusively to the selected provider</label>
        <div class="grid grid-cols-2 gap-3">
          <button type="button" id="providerBtnAnthropic" onclick="selectProvider('anthropic')"
                  class="flex flex-col items-start gap-1 p-4 rounded-lg border-2 transition text-left">
            <span class="font-bold text-sm">Anthropic Claude</span>
            <span class="text-xs opacity-60">claude-opus, sonnet, haiku…</span>
          </button>
          <button type="button" id="providerBtnGrok" onclick="selectProvider('grok')"
                  class="flex flex-col items-start gap-1 p-4 rounded-lg border-2 transition text-left">
            <span class="font-bold text-sm">xAI Grok</span>
            <span class="text-xs opacity-60">grok-3, grok-3-mini…</span>
          </button>
        </div>
        <input type="hidden" id="cfgAiProvider" value="anthropic">
      </div>

      <!-- Anthropic key + model (shown when Anthropic is selected) -->
      <div id="anthropicSection" class="bg-slate-950 border border-slate-800 rounded p-4 space-y-3">
        <label class="block font-bold flex items-center justify-between">
          <span>Anthropic API Key</span>
          <span id="keyStatus" class="text-xs"></span>
        </label>
        <div class="flex gap-2">
          <input id="apiKey" type="password" placeholder="sk-ant-..." autocomplete="off"
                 class="flex-1 bg-slate-900 border border-slate-700 px-3 py-2 rounded focus:border-cyan-500 outline-none">
          <button id="saveKeyBtn" class="bg-cyan-600 hover:bg-cyan-500 px-4 py-2 rounded transition">Save Key</button>
        </div>
        <p class="text-xs text-slate-500">Get one at <a class="text-cyan-400 underline" href="https://console.anthropic.com" target="_blank">console.anthropic.com</a>. Stored in your local config file (<span id="configPathHint"></span>).</p>
        <div class="pt-1 border-t border-slate-800">
          <label class="block mb-1 text-slate-400">Claude Model</label>
          <select id="cfgModel" class="w-full bg-slate-900 border border-slate-700 px-3 py-2 rounded focus:border-cyan-500 outline-none">
            <option value="">— set API key to load models —</option>
          </select>
        </div>
      </div>

      <!-- Grok key + model (shown when Grok is selected) -->
      <div id="grokSection" class="hidden bg-slate-950 border border-slate-800 rounded p-4 space-y-3">
        <label class="block font-bold flex items-center justify-between">
          <span>xAI Grok API Key</span>
          <span id="grokKeyStatus" class="text-xs"></span>
        </label>
        <div class="flex gap-2">
          <input id="grokKey" type="password" placeholder="xai-..." autocomplete="off"
                 class="flex-1 bg-slate-900 border border-slate-700 px-3 py-2 rounded focus:border-cyan-500 outline-none">
          <button id="saveGrokKeyBtn" class="bg-cyan-600 hover:bg-cyan-500 px-4 py-2 rounded transition">Save Key</button>
        </div>
        <p class="text-xs text-slate-500">Get one at <a class="text-cyan-400 underline" href="https://console.x.ai" target="_blank">console.x.ai</a>. Stored in the same local config file.</p>
        <div class="pt-1 border-t border-slate-800">
          <label class="block mb-1 text-slate-400">Grok Model</label>
          <select id="cfgGrokModel" class="w-full bg-slate-900 border border-slate-700 px-3 py-2 rounded focus:border-cyan-500 outline-none">
            <option value="">— set API key to load models —</option>
          </select>
        </div>
      </div>

      </div><!-- end aiSettingsBlock -->

      <!-- Targets -->
      <div>
        <label class="block mb-1 text-slate-400">Targets</label>
        <textarea id="cfgTargets" rows="3" class="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded focus:border-cyan-500 outline-none font-mono"></textarea>
        <p class="mt-1 text-xs text-slate-500">IP addresses or hostnames to ICMP ping, one per line.</p>
      </div>

      <!-- Interfaces -->
      <div class="grid sm:grid-cols-2 gap-4">
        <div>
          <label class="block mb-1 text-slate-400">Capture interface</label>
          <select id="cfgInterface" class="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded focus:border-cyan-500 outline-none">
            <option value="">Loading…</option>
          </select>
          <p class="mt-1 text-xs text-slate-500">Interface tshark/tcpdump listens on.</p>
        </div>
        <div>
          <label class="block mb-1 text-slate-400">Egress interface <span class="text-slate-600">(LLM / internet)</span></label>
          <select id="cfgEgressInterface" class="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded focus:border-cyan-500 outline-none">
            <option value="">Loading…</option>
          </select>
          <p class="mt-1 text-xs text-slate-500">Interface used for API calls to Claude / Grok. Leave blank for OS default.</p>
        </div>
      </div>

      <!-- Numeric trio -->
      <div class="grid sm:grid-cols-3 gap-4">
        <div>
          <label class="block mb-1 text-slate-400">Loss threshold (%)</label>
          <input id="cfgThreshold" type="number" min="1" max="100" class="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded outline-none">
          <p class="mt-1 text-xs text-slate-500">Packet-loss % that triggers a capture. Lower = more sensitive.</p>
        </div>
        <div>
          <label class="block mb-1 text-slate-400">Window size</label>
          <input id="cfgWindow" type="number" min="2" class="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded outline-none">
          <p class="mt-1 text-xs text-slate-500">Rolling count of recent pings used to calculate loss %. Larger = smoother but slower to react.</p>
        </div>
        <div>
          <label class="block mb-1 text-slate-400">Ping interval (s)</label>
          <input id="cfgInterval" type="number" step="0.1" min="0.1" class="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded outline-none">
          <p class="mt-1 text-xs text-slate-500">Seconds between ping rounds. Shorter = faster detection.</p>
        </div>
      </div>

      <!-- Capture trio -->
      <div class="grid sm:grid-cols-3 gap-4">
        <div>
          <label class="block mb-1 text-slate-400">Capture duration (s)</label>
          <input id="cfgCaptureDur" type="number" min="5" class="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded outline-none">
          <p class="mt-1 text-xs text-slate-500">How long tshark records traffic once a capture is triggered.</p>
        </div>
        <div>
          <label class="block mb-1 text-slate-400">Cooldown (s)</label>
          <input id="cfgCooldown" type="number" min="0" class="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded outline-none">
          <p class="mt-1 text-xs text-slate-500">Minimum seconds between captures to prevent repeated triggers during sustained loss.</p>
        </div>
        <div>
          <label class="block mb-1 text-slate-400">Pre-buffer (s)</label>
          <input id="cfgPrebufferSecs" type="number" min="2" class="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded outline-none">
          <p class="mt-1 text-xs text-slate-500">Ring-buffer file rotation interval. Up to 3× this amount of pre-outage traffic is preserved.</p>
        </div>
      </div>

      <!-- Capture directory with folder browser -->
      <div>
        <label class="block mb-1 text-slate-400">Capture directory</label>
        <div class="flex gap-2">
          <input id="cfgCaptureDir" class="flex-1 bg-slate-950 border border-slate-700 px-3 py-2 rounded outline-none font-mono">
          <button id="browseBtn" type="button" class="bg-slate-700 hover:bg-slate-600 px-3 py-2 rounded transition text-xs">Browse</button>
        </div>
        <p class="mt-1 text-xs text-slate-500">Where pcap files are written on disk. Must be writable by this process.</p>
      </div>

      <!-- Pre-buffer toggle -->
      <div>
        <label class="flex items-center gap-2 cursor-pointer">
          <input id="cfgPrebufferEnabled" type="checkbox" class="w-4 h-4 accent-cyan-500">
          <span>Pre-buffer enabled</span>
        </label>
        <p class="mt-1 text-xs text-slate-500 ml-6">Runs tshark continuously in the background, discarding output. On trigger, the last N pre-buffer seconds are merged into the capture so the moments before an outage are included.</p>
      </div>

    </div>
    <div class="flex justify-end gap-2 p-5 border-t border-slate-800">
      <button id="cancelBtn" class="bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded transition">Cancel</button>
      <button id="saveBtn" class="bg-cyan-600 hover:bg-cyan-500 px-4 py-2 rounded font-bold transition">Save Settings</button>
    </div>
  </div>
</div>

<!-- Folder Picker Modal -->
<div id="folderPickerModal" class="hidden fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
  <div class="bg-slate-900 border border-slate-800 rounded-lg w-full max-w-lg">
    <div class="flex justify-between items-center p-4 border-b border-slate-800">
      <h3 class="font-bold text-sm">Select Folder</h3>
      <button onclick="closeFolderPicker()" class="text-slate-400 hover:text-white text-2xl leading-none">&times;</button>
    </div>
    <div class="p-4 space-y-3">
      <div id="fpPath" class="text-xs text-slate-400 font-mono break-all bg-slate-950 px-3 py-2 rounded"></div>
      <div id="fpDirs" class="space-y-0.5 max-h-72 overflow-y-auto"></div>
    </div>
    <div class="flex justify-end gap-2 p-4 border-t border-slate-800">
      <button onclick="closeFolderPicker()" class="bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded text-sm transition">Cancel</button>
      <button onclick="selectCurrentFolder()" class="bg-cyan-600 hover:bg-cyan-500 px-4 py-2 rounded font-bold text-sm transition">Select this folder</button>
    </div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);

function lossColor(p)   { return p < 10 ? 'text-emerald-400' : p < 30 ? 'text-amber-400' : 'text-red-400'; }
function statusBadge(p) {
  if (p === 0)  return ['OK',       'bg-emerald-950 text-emerald-400 border-emerald-800'];
  if (p < 30)   return ['DEGRADED', 'bg-amber-950 text-amber-400 border-amber-800'];
                 return ['DOWN',    'bg-red-950 text-red-400 border-red-800'];
}
function levelColor(l) {
  return ({INFO:'text-emerald-400',WARN:'text-amber-400',ERROR:'text-red-400',CAPTURE:'text-fuchsia-400',ANALYSIS:'text-cyan-400'})[l] || 'text-slate-400';
}
function renderHistory(snap) {
  return snap.map(ok => `<span class="${ok?'text-emerald-400':'text-red-400'}">${ok?'●':'○'}</span>`).join('');
}
function fmtSize(b) {
  if (b < 1024)        return b + ' B';
  if (b < 1024*1024)   return (b/1024).toFixed(1) + ' KB';
  return (b/1024/1024).toFixed(1) + ' MB';
}

function toggleAiEnabled(enabled) {
  $('aiSettingsBlock').classList.toggle('hidden', !enabled);
  scheduleAutoSave();
}

function selectProvider(p) {
  $('cfgAiProvider').value = p;
  const isAnthropic = p === 'anthropic';
  // Show/hide key sections
  $('anthropicSection').classList.toggle('hidden', !isAnthropic);
  $('grokSection').classList.toggle('hidden', isAnthropic);
  // Style active button: cyan border + tinted background
  const activeBtn  = isAnthropic ? $('providerBtnAnthropic') : $('providerBtnGrok');
  const inactiveBtn = isAnthropic ? $('providerBtnGrok') : $('providerBtnAnthropic');
  activeBtn.className   = 'flex flex-col items-start gap-1 p-4 rounded-lg border-2 transition text-left border-cyan-500 bg-cyan-950 text-cyan-200';
  inactiveBtn.className = 'flex flex-col items-start gap-1 p-4 rounded-lg border-2 transition text-left border-slate-700 bg-slate-950 text-slate-400';
  scheduleAutoSave();
}

const _expandedAnalyses = new Set();
const _renderedAnalysisIds = new Set();
function toggleAnalysis(id) {
  const body = document.getElementById('ab-' + id);
  const chevron = document.getElementById('ac-' + id);
  if (!body) return;
  const open = !body.classList.contains('hidden');
  body.classList.toggle('hidden', open);
  chevron.textContent = open ? '▶ show' : '▼ hide';
  open ? _expandedAnalyses.delete(id) : _expandedAnalyses.add(id);
}

async function refresh() {
  try {
    const r = await fetch('/api/status');
    const s = await r.json();

    $('statusDot').className = s.running
      ? 'text-emerald-400 text-3xl leading-none animate-pulse'
      : 'text-slate-600 text-3xl leading-none';
    $('toggleBtn').textContent = s.running ? 'Stop' : 'Start';
    $('toggleBtn').className = s.running
      ? 'bg-red-600 hover:bg-red-500 px-5 py-2 rounded font-bold transition'
      : 'bg-emerald-600 hover:bg-emerald-500 px-5 py-2 rounded font-bold transition';

    $('interface').textContent = s.interface || '—';
    $('tool').textContent = s.tool || '—';
    $('uptime').textContent = s.uptime;
    $('cooldown').textContent = s.cooldown_remaining > 0 ? `${Math.ceil(s.cooldown_remaining)}s` : '—';

    $('targets').innerHTML = s.targets.map(t => {
      const loss = s.loss_pct[t] || 0;
      const snap = s.window_snaps[t] || [];
      const [badge, badgeCls] = statusBadge(loss);
      return `
        <div class="flex items-center gap-3 p-2 bg-slate-950 rounded">
          <span class="font-bold w-32 truncate">${t}</span>
          <span class="${lossColor(loss)} w-16 text-right text-sm">${loss.toFixed(1)}%</span>
          <span class="flex-1 truncate text-center text-base tracking-wider">${renderHistory(snap)}</span>
          <span class="text-xs px-2 py-0.5 rounded border ${badgeCls}">${badge}</span>
        </div>`;
    }).join('') || '<div class="text-slate-500 italic text-sm">No targets configured (open Settings)</div>';

    const capList = s.capturing_targets || [];
    if (capList.length > 0) {
      $('captureStatus').classList.remove('hidden');
      $('captureStatus').innerHTML = capList.map(c => {
        const elapsed = c.elapsed || 0;
        const total = c.duration || 30;
        const pct = Math.min(100, (elapsed / total) * 100);
        return `
          <div>
            <div class="text-fuchsia-300 text-sm flex justify-between">
              <span>⟳ Capturing <span class="font-bold">${c.target}</span></span>
              <span class="text-fuchsia-400">${Math.floor(elapsed)}s / ${total}s</span>
            </div>
            <div class="bg-slate-950 rounded h-2 mt-2 overflow-hidden">
              <div class="bg-fuchsia-500 h-full transition-all" style="width:${pct}%"></div>
            </div>
          </div>`;
      }).join('');
    } else {
      $('captureStatus').classList.add('hidden');
      $('captureStatus').innerHTML = '';
    }

    const analyzeList = s.analyzing_targets || [];
    if (analyzeList.length > 0) {
      $('analyzeStatus').classList.remove('hidden');
      $('analyzeStatus').innerHTML = analyzeList.map(t => `
        <div class="flex items-center gap-2 text-amber-300 text-sm">
          <span class="animate-spin inline-block">⟳</span>
          <span>Waiting for LLM analysis — <span class="font-bold">${t}</span></span>
        </div>`).join('');
    } else {
      $('analyzeStatus').classList.add('hidden');
      $('analyzeStatus').innerHTML = '';
    }

    const analyses = s.analyses || [];
    if (analyses.length === 0) {
      if (_renderedAnalysisIds.size === 0) {
        $('analysisList').innerHTML = '<p class="text-slate-500 italic text-sm">Waiting for first capture event…</p>';
      }
    } else {
      const newEntries = analyses.filter(a => !_renderedAnalysisIds.has(a.id));
      if (newEntries.length > 0) {
        // Auto-expand the newest (first) entry
        if (newEntries.length > 0) _expandedAnalyses.add(newEntries[0].id);
        $('analysisList').innerHTML = analyses.map(a => {
          const open = _expandedAnalyses.has(a.id);
          _renderedAnalysisIds.add(a.id);
          return `
            <div class="border border-slate-700 rounded mb-2">
              <button onclick="toggleAnalysis('${a.id}')" class="w-full flex justify-between items-center px-3 py-2 text-left hover:bg-slate-800 rounded">
                <span class="text-xs font-bold text-cyan-400">
                  ${a.target}
                  <span class="text-slate-500 font-normal ml-2">${a.time}</span>
                </span>
                <span id="ac-${a.id}" class="text-slate-500 text-xs">${open ? '▼ hide' : '▶ show'}</span>
              </button>
              <div id="ab-${a.id}" class="${open ? '' : 'hidden'} px-3 pb-3">
                <div class="markdown text-sm leading-relaxed text-slate-300">${marked.parse(a.text)}</div>
              </div>
            </div>`;
        }).join('');
      }
    }

    $('events').innerHTML = s.events.map(e => `
      <div class="flex gap-3">
        <span class="text-slate-600 w-16">${e[0]}</span>
        <span class="${levelColor(e[1])} w-20 font-bold">[${e[1]}]</span>
        <span class="flex-1">${e[2]}</span>
      </div>`).join('') || '<div class="text-slate-600 italic">No events yet</div>';

    const caps = s.captures || [];
    $('captures').innerHTML = caps.length === 0
      ? '<div class="text-slate-600 italic">No captures yet</div>'
      : caps.map(c => `
          <div class="flex items-center gap-3 p-2 bg-slate-950 rounded">
            <span class="flex-1 truncate text-xs">${c.name}</span>
            <span class="text-slate-500 text-xs w-20 text-right">${fmtSize(c.size)}</span>
            <span class="text-slate-500 text-xs w-32 text-right">${c.modified}</span>
            <button onclick="openCapture('${c.name}')" class="bg-cyan-600 hover:bg-cyan-500 px-3 py-1 rounded text-xs transition">Open</button>
            <button onclick="deleteCapture('${c.name}')" class="bg-slate-800 hover:bg-red-700 px-2 py-1 rounded text-xs transition">×</button>
          </div>`).join('');
  } catch (err) {
    console.error('refresh failed', err);
  }
}

async function openCapture(name) {
  await fetch('/api/captures/' + encodeURIComponent(name) + '/open', {method: 'POST'});
}

async function deleteCapture(name) {
  if (!confirm('Delete ' + name + '?')) return;
  await fetch('/api/captures/' + encodeURIComponent(name), {method: 'DELETE'});
  refresh();
}

$('toggleBtn').addEventListener('click', async () => {
  const r = await fetch('/api/status').then(r => r.json());
  const action = r.running ? 'stop' : 'start';
  const resp = await fetch('/api/control/' + action, {method: 'POST'}).then(r => r.json());
  if (!resp.ok) alert(resp.error);
  refresh();
});

async function loadModels(currentModel) {
  const sel = $('cfgModel');
  sel.innerHTML = '<option value="">Loading…</option>';
  const r = await fetch('/api/models').then(r => r.json());
  if (!r.models || r.models.length === 0) {
    sel.innerHTML = '<option value="">' + (r.error || 'Set API key above to load models') + '</option>';
    return;
  }
  sel.innerHTML = r.models.map(m =>
    `<option value="${m}" ${m === currentModel ? 'selected' : ''}>${m}</option>`
  ).join('');
  if (!r.models.includes(currentModel) && currentModel) {
    sel.insertAdjacentHTML('afterbegin', `<option value="${currentModel}" selected>${currentModel}</option>`);
  }
}

async function loadGrokModels(currentModel) {
  const sel = $('cfgGrokModel');
  sel.innerHTML = '<option value="">Loading…</option>';
  let r;
  try { r = await fetch('/api/grok-models').then(res => res.json()); }
  catch (e) { r = {models: [], error: String(e)}; }
  if (!r.models || r.models.length === 0) {
    sel.innerHTML = `<option value="">${r.error || 'Set Grok API key above to load models'}</option>`;
    // Inject a retry button below the select
    const existing = sel.nextElementSibling;
    if (existing && existing.dataset.retryBtn) existing.remove();
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.dataset.retryBtn = '1';
    btn.textContent = '↻ Retry loading models';
    btn.className = 'mt-1 text-xs text-cyan-400 hover:text-cyan-300 underline';
    btn.onclick = () => loadGrokModels(sel.value);
    sel.insertAdjacentElement('afterend', btn);
    return;
  }
  // Remove retry btn if present
  const existing = sel.nextElementSibling;
  if (existing && existing.dataset.retryBtn) existing.remove();
  sel.innerHTML = r.models.map(m =>
    `<option value="${m}" ${m === currentModel ? 'selected' : ''}>${m}</option>`
  ).join('');
  if (!r.models.includes(currentModel) && currentModel) {
    sel.insertAdjacentHTML('afterbegin', `<option value="${currentModel}" selected>${currentModel}</option>`);
  }
}

async function openSettings() {
  const [c, k, gk, ifaces] = await Promise.all([
    fetch('/api/config').then(r => r.json()),
    fetch('/api/api-key/status').then(r => r.json()),
    fetch('/api/grok-key/status').then(r => r.json()),
    fetch('/api/interfaces').then(r => r.json()),
  ]);
  const sel = $('cfgInterface');
  const current = c.interface;
  const rawOpts = ifaces.interfaces || [];
  // Normalize to {value, label} objects (API always returns objects now)
  const opts = rawOpts.map(i => typeof i === 'string' ? {value: i, label: i} : i);
  if (!opts.some(o => o.value === current) && current) opts.unshift({value: current, label: current});
  sel.innerHTML = opts.map(o => `<option value="${o.value}"${o.value === current ? ' selected' : ''}>${o.label}</option>`).join('');

  const esel = $('cfgEgressInterface');
  const ecurrent = c.egress_interface || '';
  const eopts = [{value: '', label: '— OS default —'}].concat(opts);
  esel.innerHTML = eopts.map(o => `<option value="${o.value}"${o.value === ecurrent ? ' selected' : ''}>${o.label}</option>`).join('');

  $('cfgTargets').value = c.targets.join('\n');
  $('cfgInterface').value = c.interface;
  $('cfgThreshold').value = c.loss_threshold;
  $('cfgWindow').value = c.window_size;
  $('cfgInterval').value = c.ping_interval;
  $('cfgCaptureDur').value = c.capture_duration;
  $('cfgCooldown').value = c.cooldown_secs;
  $('cfgPrebufferSecs').value = c.prebuffer_secs;
  $('cfgPrebufferEnabled').checked = c.prebuffer_enabled;
  $('cfgCaptureDir').value = c.capture_dir;
  $('cfgInterface').value = current;

  const aiEnabled = c.ai_enabled !== false;
  $('cfgAiEnabled').checked = aiEnabled;
  $('aiSettingsBlock').classList.toggle('hidden', !aiEnabled);
  selectProvider(c.ai_provider || 'anthropic');
  if (c.config_path) $('configPathHint').textContent = c.config_path;

  $('keyStatus').textContent = k.set ? 'saved ✓' : 'not set';
  $('keyStatus').className = k.set ? 'text-xs text-emerald-400' : 'text-xs text-amber-400';
  $('apiKey').value = '';
  if (k.set) { loadModels(c.claude_model); }
  else { $('cfgModel').innerHTML = '<option value="">— set API key above, then save —</option>'; }

  $('grokKeyStatus').textContent = gk.set ? 'saved ✓' : 'not set';
  $('grokKeyStatus').className = gk.set ? 'text-xs text-emerald-400' : 'text-xs text-amber-400';
  $('grokKey').value = '';
  if (gk.set) { loadGrokModels(c.grok_model); }
  else { $('cfgGrokModel').innerHTML = '<option value="">— set API key above, then save —</option>'; }

  $('settingsModal').classList.remove('hidden');
}

function closeSettings() {
  $('settingsModal').classList.add('hidden');
}
$('clearBtn').addEventListener('click', async () => {
  await fetch('/api/control/clear', {method: 'POST'});
  _expandedAnalyses.clear();
  _renderedAnalysisIds.clear();
  $('analysisList').innerHTML = '<p class="text-slate-500 italic text-sm">Waiting for first capture event…</p>';
  refresh();
});
$('settingsBtn').addEventListener('click', openSettings);
$('cancelBtn').addEventListener('click', closeSettings);
$('closeSettings').addEventListener('click', closeSettings);
$('refreshCapsBtn').addEventListener('click', refresh);

// ── Folder Picker Modal ───────────────────────────────────────────────────────
let _fpCurrentPath = '';
const _fpPaths = {};

async function _fpBrowseTo(path) {
  const r = await fetch('/api/browse?path=' + encodeURIComponent(path)).then(r => r.json());
  if (r.error && !r.path) return;
  _fpCurrentPath = r.path;
  $('fpPath').textContent = r.path;
  Object.keys(_fpPaths).forEach(k => delete _fpPaths[k]);
  let html = '';
  if (!r.is_root) {
    _fpPaths['__up__'] = r.parent;
    html += `<button class="fp-item w-full text-left px-3 py-1.5 rounded hover:bg-slate-800 text-slate-400 text-sm font-mono" data-key="__up__">↑  ..</button>`;
  }
  (r.dirs || []).forEach((d, i) => {
    const key = 'k' + i;
    _fpPaths[key] = d.path;
    html += `<button class="fp-item w-full text-left px-3 py-1.5 rounded hover:bg-slate-800 text-sm font-mono truncate" data-key="${key}">📁  ${d.name}</button>`;
  });
  $('fpDirs').innerHTML = html || '<div class="text-slate-500 italic text-sm px-3 py-2">No subdirectories</div>';
  $('fpDirs').querySelectorAll('.fp-item').forEach(btn => {
    btn.addEventListener('click', () => _fpBrowseTo(_fpPaths[btn.dataset.key]));
  });
}

async function openFolderPicker() {
  // macOS: use native Finder dialog; everything else: use in-page picker
  if (navigator.platform.startsWith('Mac')) {
    const cur = $('cfgCaptureDir').value.trim() || '.';
    $('browseBtn').disabled = true;
    $('browseBtn').textContent = '…';
    try {
      const r = await fetch('/api/browse-native?path=' + encodeURIComponent(cur)).then(r => r.json());
      if (r.path) $('cfgCaptureDir').value = r.path;
    } finally {
      $('browseBtn').disabled = false;
      $('browseBtn').textContent = 'Browse';
    }
    return;
  }
  _fpBrowseTo($('cfgCaptureDir').value.trim() || '.');
  $('folderPickerModal').classList.remove('hidden');
}
function closeFolderPicker() {
  $('folderPickerModal').classList.add('hidden');
}
function selectCurrentFolder() {
  if (_fpCurrentPath) { $('cfgCaptureDir').value = _fpCurrentPath; scheduleAutoSave(); }
  closeFolderPicker();
}

$('browseBtn').addEventListener('click', openFolderPicker);

// ── Auto-save settings on any change ──────────────────────────────────────────
function collectCfg() {
  const sel = $('cfgModel');
  const gsel = $('cfgGrokModel');
  return {
    targets: $('cfgTargets').value.split('\n').map(s=>s.trim()).filter(Boolean),
    interface: $('cfgInterface').value.trim(),
    egress_interface: $('cfgEgressInterface').value,
    claude_model: sel.value || sel.options[sel.selectedIndex]?.text || '',
    grok_model: gsel.value || gsel.options[gsel.selectedIndex]?.text || '',
    ai_provider: $('cfgAiProvider').value,
    ai_enabled: $('cfgAiEnabled').checked,
    loss_threshold: parseInt($('cfgThreshold').value) || 0,
    window_size: parseInt($('cfgWindow').value) || 0,
    ping_interval: parseFloat($('cfgInterval').value) || 0,
    capture_duration: parseInt($('cfgCaptureDur').value) || 0,
    cooldown_secs: parseInt($('cfgCooldown').value) || 0,
    prebuffer_secs: parseInt($('cfgPrebufferSecs').value) || 0,
    prebuffer_enabled: $('cfgPrebufferEnabled').checked,
    capture_dir: $('cfgCaptureDir').value.trim(),
  };
}
let _saveTimer = null;
function scheduleAutoSave() {
  clearTimeout(_saveTimer);
  _saveTimer = setTimeout(() => {
    fetch('/api/config', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(collectCfg()),
    });
  }, 600);
}
['cfgTargets','cfgThreshold','cfgWindow','cfgInterval','cfgCaptureDur','cfgCooldown','cfgPrebufferSecs','cfgCaptureDir']
  .forEach(id => $(id).addEventListener('input', scheduleAutoSave));
['cfgInterface','cfgEgressInterface','cfgModel','cfgGrokModel','cfgPrebufferEnabled']
  .forEach(id => $(id).addEventListener('change', scheduleAutoSave));

$('saveBtn').addEventListener('click', async () => {
  clearTimeout(_saveTimer);
  const r = await fetch('/api/config', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(collectCfg()),
  }).then(r => r.json());
  if (!r.ok) { alert(r.error); return; }
  closeSettings();
  refresh();
});

$('saveKeyBtn').addEventListener('click', async () => {
  const key = $('apiKey').value.trim();
  if (!key) return;
  const r = await fetch('/api/api-key', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({key}),
  }).then(r => r.json());
  if (!r.ok) { alert(r.error); return; }
  $('keyStatus').textContent = 'saved ✓';
  $('keyStatus').className = 'text-xs text-emerald-400';
  $('apiKey').value = '';
  loadModels($('cfgModel').value);
});

$('saveGrokKeyBtn').addEventListener('click', async () => {
  const key = $('grokKey').value.trim();
  if (!key) return;
  const r = await fetch('/api/grok-key', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({key}),
  }).then(r => r.json());
  if (!r.ok) { alert(r.error); return; }
  $('grokKeyStatus').textContent = 'saved ✓';
  $('grokKeyStatus').className = 'text-xs text-emerald-400';
  $('grokKey').value = '';
  loadGrokModels($('cfgGrokModel').value);
});

refresh();
setInterval(refresh, 1000);
setInterval(() => fetch('/api/heartbeat', {method:'POST'}), 5000);
</script>
</body>
</html>
"""


def create_app(controller: Controller) -> Flask:
    """Build the Flask app with all routes wired to the controller."""
    app = Flask(__name__)
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.WARNING)

    @app.route("/")
    def index():
        return _HTML

    @app.route("/api/status")
    def status():
        return jsonify(controller.get_state())

    @app.route("/api/config", methods=["GET", "POST"])
    def config():
        if request.method == "GET":
            d = controller.config.to_dict()
            d["config_path"] = str(_CONFIG_PATH)
            return jsonify(d)
        ok, msg = controller.update_config(request.get_json(force=True) or {})
        return jsonify({"ok": ok, "error": None if ok else msg, "message": msg})

    @app.route("/api/control/start", methods=["POST"])
    def control_start():
        ok, msg = controller.start()
        return jsonify({"ok": ok, "error": None if ok else msg, "message": msg})

    @app.route("/api/control/stop", methods=["POST"])
    def control_stop():
        ok, msg = controller.stop()
        return jsonify({"ok": ok, "error": None if ok else msg, "message": msg})

    @app.route("/api/control/clear", methods=["POST"])
    def control_clear():
        if controller.state is not None:
            controller.state.clear()
        return jsonify({"ok": True})

    @app.route("/api/api-key", methods=["POST"])
    def api_key_set():
        body = request.get_json(force=True) or {}
        key = (body.get("key") or "").strip()
        if not key:
            return jsonify({"ok": False, "error": "Empty key"}), 400
        save_api_key(key)
        os.environ["ANTHROPIC_API_KEY"] = key
        return jsonify({"ok": True})

    @app.route("/api/api-key/status")
    def api_key_status():
        return jsonify({"set": bool(os.environ.get("ANTHROPIC_API_KEY"))})

    @app.route("/api/grok-key", methods=["POST"])
    def grok_key_set():
        body = request.get_json(force=True) or {}
        key = (body.get("key") or "").strip()
        if not key:
            return jsonify({"ok": False, "error": "Empty key"}), 400
        save_grok_api_key(key)
        os.environ["GROK_API_KEY"] = key
        return jsonify({"ok": True})

    @app.route("/api/grok-key/status")
    def grok_key_status():
        return jsonify({"set": bool(os.environ.get("GROK_API_KEY"))})

    @app.route("/api/grok-models")
    def grok_models_list():
        key = os.environ.get("GROK_API_KEY")
        if not key:
            return jsonify({"models": [], "error": "No Grok API key set"})
        try:
            req = urllib.request.Request(
                "https://api.x.ai/v1/models",
                headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            # Only include chat/text models — exclude image and video generation
            _skip = ("imagine", "image", "video")
            ids = sorted(
                m["id"] for m in data.get("data", [])
                if not any(s in m["id"].lower() for s in _skip)
            )
            return jsonify({"models": ids})
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            return jsonify({"models": [], "error": f"xAI API {exc.code}: {body}"})
        except Exception as exc:
            return jsonify({"models": [], "error": str(exc)})

    @app.route("/api/models")
    def models_list():
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            return jsonify({"models": [], "error": "No API key set"})
        try:
            client = anthropic.Anthropic(api_key=key)
            result = client.models.list(limit=100)
            ids = [m.id for m in result.data]
            return jsonify({"models": ids})
        except Exception as exc:
            return jsonify({"models": [], "error": str(exc)})

    @app.route("/api/interfaces")
    def list_interfaces():
        ifaces = []
        try:
            out = subprocess.check_output(["tshark", "-D"], stderr=subprocess.STDOUT, text=True)
            import re
            for line in out.splitlines():
                m = re.match(r"^\d+\.\s+(\S+)(?:\s+\((.+)\))?", line)
                if m:
                    device, friendly = m.group(1), m.group(2)
                    ifaces.append({"value": device, "label": friendly if friendly else device})
        except Exception:
            pass
        if not ifaces:
            try:
                import socket
                ifaces = [{"value": name, "label": name} for _, name in socket.if_nameindex()]
            except Exception:
                pass
        return jsonify({"interfaces": ifaces})

    @app.route("/api/browse")
    def browse():
        raw = request.args.get("path", ".")
        try:
            p = Path(raw).expanduser().resolve()
            if not p.is_dir():
                p = p.parent
            dirs = sorted(
                ({"name": d.name, "path": str(d)} for d in p.iterdir() if d.is_dir() and not d.name.startswith(".")),
                key=lambda x: x["name"].lower(),
            )
            return jsonify({"path": str(p), "parent": str(p.parent), "is_root": p == p.parent, "dirs": dirs})
        except PermissionError:
            return jsonify({"path": str(p), "parent": str(p.parent), "is_root": False, "dirs": [], "error": "Permission denied"})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/browse-native")
    def browse_native():
        cur = request.args.get("path", str(Path.home()))
        p = Path(cur).expanduser().resolve()
        if not p.is_dir():
            p = p.parent

        try:
            if sys.platform == "darwin":
                script = (
                    f'tell application "Finder" to activate\n'
                    f'set chosen to choose folder with prompt "Select capture directory" '
                    f'default location (POSIX file "{p}")\n'
                    f'POSIX path of chosen'
                )
                result = subprocess.run(
                    ["osascript", "-e", script],
                    capture_output=True, text=True, timeout=300,
                )
                chosen = result.stdout.strip().rstrip("/")
                return jsonify({"path": chosen or None})

            elif sys.platform == "win32":
                path_str = str(p).replace('"', '`"')
                ps = (
                    "Add-Type -AssemblyName System.Windows.Forms; "
                    "$f = New-Object System.Windows.Forms.FolderBrowserDialog; "
                    "$f.Description = 'Select capture directory'; "
                    f'$f.SelectedPath = "{path_str}"; '
                    "$f.ShowNewFolderButton = $true; "
                    "if ($f.ShowDialog() -eq 'OK') { $f.SelectedPath }"
                )
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps],
                    capture_output=True, text=True, timeout=300,
                )
                chosen = result.stdout.strip()
                return jsonify({"path": chosen or None})

            else:
                # Linux — try zenity (GTK), fall back gracefully
                result = subprocess.run(
                    ["zenity", "--file-selection", "--directory", f"--filename={p}/"],
                    capture_output=True, text=True, timeout=300,
                )
                chosen = result.stdout.strip()
                return jsonify({"path": chosen or None})

        except FileNotFoundError:
            return jsonify({"path": None})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/captures")
    def captures_list():
        return jsonify(controller._list_captures())

    @app.route("/api/captures/<path:filename>")
    def captures_download(filename):
        d = Path(controller.config.capture_dir).resolve()
        target = (d / filename).resolve()
        # Path traversal guard
        if not str(target).startswith(str(d)) or not target.exists() or not target.is_file():
            abort(404)
        return send_file(str(target), as_attachment=True, download_name=target.name)

    @app.route("/api/captures/<path:filename>/open", methods=["POST"])
    def captures_open(filename):
        d = Path(controller.config.capture_dir).resolve()
        target = (d / filename).resolve()
        if not str(target).startswith(str(d)) or not target.exists() or not target.is_file():
            abort(404)
        if sys.platform == "win32":
            os.startfile(str(target))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)])
        else:
            subprocess.Popen(["xdg-open", str(target)])
        return "", 204

    @app.route("/api/captures/<path:filename>", methods=["DELETE"])
    def captures_delete(filename):
        d = Path(controller.config.capture_dir).resolve()
        target = (d / filename).resolve()
        if not str(target).startswith(str(d)) or not target.exists():
            abort(404)
        try:
            target.unlink()
            return jsonify({"ok": True})
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

    @app.route("/api/heartbeat", methods=["POST"])
    def heartbeat():
        _heartbeat_time[0] = time.time()
        return "", 204

    return app


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    print("", flush=True)
    print(f"  NetWatch v{__version__} — starting up", flush=True)
    print("  ─────────────────────────────────", flush=True)
    if getattr(sys, "frozen", False):
        print("  [ok] Bundle extracted.", flush=True)

    host = os.environ.get("NETWATCH_HOST", "127.0.0.1")
    port = int(os.environ.get("NETWATCH_PORT", "8765"))

    # Windows reserves dynamic port ranges (Hyper-V / WSL / Docker) that often
    # contain otherwise-unused ports. Trying to bind one returns WSAEACCES and
    # crashes Flask. Probe candidate ports and fall back to the next free one.
    def _port_is_bindable(p: int) -> bool:
        import socket as _socket
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        try:
            s.bind((host, p))
            return True
        except OSError:
            return False
        finally:
            s.close()

    if not _port_is_bindable(port):
        original = port
        for candidate in [8765, 8080, 8181, 8866, 9090, 9876, 0]:
            if candidate == original:
                continue
            if candidate == 0 or _port_is_bindable(candidate):
                # candidate==0 means "let the OS pick" — bind once to discover the port.
                if candidate == 0:
                    import socket as _socket
                    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                    s.bind((host, 0))
                    candidate = s.getsockname()[1]
                    s.close()
                print(f"  [..] Port {original} is reserved by Windows — using {candidate} instead.",
                      flush=True)
                port = candidate
                break

    # On Windows, prepend bundled tshark to PATH and install Npcap if missing,
    # before any capture code path runs.
    if sys.platform == "win32":
        bundled = _bundled_wireshark_dir()
        if bundled is not None:
            os.environ["PATH"] = str(bundled) + os.pathsep + os.environ.get("PATH", "")
            print(f"  [ok] Using bundled tshark at {bundled}", flush=True)
        else:
            print("  [..] No bundled tshark found — falling back to system PATH.", flush=True)
        ensure_npcap_windows()

    print("  [..] Starting web server…", flush=True)
    controller = Controller()
    app = create_app(controller)

    url = f"http://{host}:{port}"
    print(f"\n  NetWatch web UI  →  {url}")
    print(f"  Config saved at  →  {_CONFIG_PATH}")
    print(f"  Press Ctrl-C to stop\n", flush=True)

    # Watchdog: exit when the browser tab has been closed for >30 s.
    # Only activates after the first heartbeat (so startup delay doesn't count).
    def _watchdog() -> None:
        TIMEOUT = 30
        while True:
            time.sleep(5)
            t = _heartbeat_time[0]
            if t is not None and (time.time() - t) > TIMEOUT:
                print("\n[netwatch] Browser closed — shutting down.")
                os._exit(0)
    threading.Thread(target=_watchdog, daemon=True).start()

    # Open browser in background after a brief delay
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    try:
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        controller.stop()
        print("\n  Stopped.")


if __name__ == "__main__":
    main()
