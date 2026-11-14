"""Probe Windows ETW Kernel-Network events for short-lived HTTPS traffic.

Run from an elevated PowerShell terminal at the repository root:
    python tools/diagnose_etw_short_lived_connections.py

This is an investigation tool only. It does not change NetTrack's production
monitoring engine. It captures separate persistent and short-lived test phases,
then checks ETW event payloads for this process ID and byte counts.
"""

import ctypes
import http.client
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlencode
import ssl

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

HOST = "speed.cloudflare.com"
PROVIDER = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
KEYWORDS_IPV4_IPV6 = "0x30"
TRACE_LEVEL = "5"
CONTROL_BYTES = 16 * 1024
BURST_BYTES = 4 * 1024
BURST_CONNECTIONS = 2
TIMEOUT_SECONDS = 30

SEND_EVENT_IDS = {10, 26, 42, 58}
RECEIVE_EVENT_IDS = {11, 27, 43, 59}
TRAFFIC_EVENT_IDS = SEND_EVENT_IDS | RECEIVE_EVENT_IDS


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def run_command(args):
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(args)}\n{details}"
        )
    return result


def transfer(connection, size):
    connection.request("GET", "/__down?" + urlencode({"bytes": size}))
    response = connection.getresponse()
    downloaded = response.read()
    if response.status != 200 or len(downloaded) != size:
        raise RuntimeError(
            f"Download failed: HTTP {response.status}, "
            f"{len(downloaded)} of {size} bytes"
        )

    payload = b"N" * size
    connection.request(
        "POST",
        "/__up",
        body=payload,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(payload)),
        },
    )
    upload_response = connection.getresponse()
    upload_response.read()
    if not 200 <= upload_response.status < 300:
        raise RuntimeError(f"Upload failed: HTTP {upload_response.status}")

    return len(payload), len(downloaded)


def make_connection():
    return http.client.HTTPSConnection(
        HOST,
        timeout=TIMEOUT_SECONDS,
        context=ssl.create_default_context(),
    )


def run_persistent_control():
    connection = make_connection()
    try:
        connection.connect()
        # Give ETW a stable established connection before the transfer.
        import time
        time.sleep(1.0)
        return transfer(connection, CONTROL_BYTES)
    finally:
        connection.close()


def run_short_lived_burst():
    sent = 0
    received = 0
    for _ in range(BURST_CONNECTIONS):
        connection = make_connection()
        try:
            connection.connect()
            current_sent, current_received = transfer(connection, BURST_BYTES)
            sent += current_sent
            received += current_received
        finally:
            connection.close()
    return sent, received


def capture_phase(session_name, etl_path, action):
    start_args = [
        "logman", "start", session_name,
        "-p", PROVIDER, KEYWORDS_IPV4_IPV6, TRACE_LEVEL,
        "-o", str(etl_path), "-ets",
    ]
    run_command(start_args)
    try:
        expected = action()
    finally:
        # Always stop the ETW session, including when the network request fails.
        run_command(["logman", "stop", session_name, "-ets"])
    return expected


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def parse_etw_events(xml_path, target_pid):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    summary = {
        "send_bytes": 0,
        "receive_bytes": 0,
        "send_events": 0,
        "receive_events": 0,
        "traffic_events_for_other_pids": 0,
        "provider_event_ids": {},
        "matched_event_ids": {},
        "unmatched_samples": [],
    }

    for event in root.iter():
        if local_name(event.tag) != "Event":
            continue

        system = next(
            (child for child in event if local_name(child.tag) == "System"),
            None,
        )
        if system is None:
            continue

        provider_name = None
        event_id = None
        for child in system:
            if local_name(child.tag) == "Provider":
                provider_name = child.attrib.get("Name")
            elif local_name(child.tag) == "EventID" and child.text:
                try:
                    event_id = int(child.text)
                except ValueError:
                    pass

        if provider_name != "Microsoft-Windows-Kernel-Network" or event_id is None:
            continue

        summary["provider_event_ids"][event_id] = (
            summary["provider_event_ids"].get(event_id, 0) + 1
        )
        if event_id not in TRAFFIC_EVENT_IDS:
            continue

        event_data = next(
            (child for child in event if local_name(child.tag) == "EventData"),
            None,
        )
        fields = {}
        if event_data is not None:
            for item in event_data:
                if local_name(item.tag) == "Data":
                    fields[item.attrib.get("Name", "")] = (item.text or "").strip()

        try:
            event_pid = int(fields.get("PID", ""))
            size = int(fields.get("size", ""))
        except ValueError:
            if len(summary["unmatched_samples"]) < 3:
                summary["unmatched_samples"].append(
                    {"event_id": event_id, "fields": fields}
                )
            continue

        if event_pid != target_pid:
            summary["traffic_events_for_other_pids"] += 1
            continue

        summary["matched_event_ids"][event_id] = (
            summary["matched_event_ids"].get(event_id, 0) + 1
        )
        if event_id in SEND_EVENT_IDS:
            summary["send_bytes"] += size
            summary["send_events"] += 1
        elif event_id in RECEIVE_EVENT_IDS:
            summary["receive_bytes"] += size
            summary["receive_events"] += 1

    return summary


def print_phase(label, expected, observed):
    print(f"\n{label}")
    print("-" * len(label))
    print(f"Expected upload payload:   {expected[0]:,} bytes")
    print(f"ETW upload event bytes:     {observed['send_bytes']:,} bytes")
    print(f"Expected download payload: {expected[1]:,} bytes")
    print(f"ETW download event bytes:   {observed['receive_bytes']:,} bytes")
    print(f"Matched send events:        {observed['send_events']}")
    print(f"Matched receive events:     {observed['receive_events']}")
    print(f"Matched event IDs:          {observed['matched_event_ids'] or 'none'}")


def main():
    print("=" * 68)
    print("NETTRACK - WINDOWS ETW SHORT-LIVED CONNECTION DIAGNOSTIC")
    print("=" * 68)
    print(f"Windows process PID: {os.getpid()}")
    print(f"ETW provider: {PROVIDER}")
    print("Capturing IPv4 and IPv6 Kernel-Network events.")
    print("This diagnostic does not modify production NetTrack code.")

    if os.name != "nt":
        raise SystemExit("This diagnostic only runs on Windows.")
    if not is_admin():
        raise SystemExit(
            "Administrator privileges are required to start this ETW session.\n"
            "Close this terminal and reopen PowerShell using 'Run as administrator'."
        )

    output_dir = Path(tempfile.mkdtemp(prefix="nettrack_etw_probe_"))
    print(f"Diagnostic files: {output_dir}")

    session_base = f"NetTrackProbe_{os.getpid()}"
    phases = [
        (
            "PERSISTENT CONTROL",
            f"{session_base}_Control",
            output_dir / "persistent_control.etl",
            run_persistent_control,
        ),
        (
            "SHORT-LIVED BURST",
            f"{session_base}_Burst",
            output_dir / "short_lived_burst.etl",
            run_short_lived_burst,
        ),
    ]

    results = []
    try:
        for label, session_name, etl_path, action in phases:
            print(f"\nCapturing {label.lower()}...")
            expected = capture_phase(session_name, etl_path, action)
            xml_path = etl_path.with_suffix(".xml")
            run_command([
                "tracerpt", str(etl_path),
                "-o", str(xml_path), "-of", "XML", "-y",
            ])
            observed = parse_etw_events(xml_path, os.getpid())
            print_phase(label, expected, observed)
            results.append((label, expected, observed))

        control = results[0][2]
        burst = results[1][2]

        print("\nETW DIAGNOSTIC SUMMARY")
        print("----------------------")
        if control["send_events"] and control["receive_events"]:
            print("PASS: ETW captured bidirectional persistent-connection events.")
        else:
            print("WARNING: ETW did not capture both directions for the control.")

        if burst["send_events"] and burst["receive_events"]:
            print("PASS: ETW captured bidirectional short-lived connection events.")
        else:
            print("WARNING: ETW did not capture both directions for the short-lived burst.")

        if not control["send_events"] and not control["receive_events"]:
            print(
                "No matching PID/size event payloads were decoded. Inspect the "
                "XML files and provider event IDs before choosing an implementation."
            )

        if burst["send_events"] and burst["receive_events"]:
            print(
                "RESULT: Kernel-Network ETW is a promising source for capturing "
                "short-lived application traffic."
            )
        else:
            print(
                "RESULT: ETW short-lived capture is not yet validated. "
                "Do not replace the existing monitor."
            )

        if any(item[2]["unmatched_samples"] for item in results):
            print("\nSample traffic events without decoded PID/size fields:")
            for label, _, observed in results:
                for sample in observed["unmatched_samples"]:
                    print(f"{label}: Event {sample['event_id']} {sample['fields']}")
        print("\nETL and XML files have been retained in the diagnostic folder.")
    finally:
        # Stop any session that may have survived a conversion or parsing error.
        for _, session_name, _, _ in phases:
            subprocess.run(
                ["logman", "stop", session_name, "-ets"],
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )


if __name__ == "__main__":
    main()
