#!/usr/bin/env python3
"""Mini SOC Log Analyzer.

Defensive log-analysis utility for identifying suspicious authentication
activity and potential brute-force behavior.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path


FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
SUCCESS_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)"
)


def analyze_log(path: str | Path, threshold: int = 5) -> dict:
    """Analyze an SSH-style authentication log."""
    if threshold < 1:
        raise ValueError("threshold must be >= 1")

    path = Path(path)
    failed_by_ip: Counter[str] = Counter()
    successful_by_ip: Counter[str] = Counter()
    total_events = 0

    with path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            failed = FAILED_RE.search(line)
            success = SUCCESS_RE.search(line)

            if failed:
                total_events += 1
                failed_by_ip[failed.group("ip")] += 1
            elif success:
                total_events += 1
                successful_by_ip[success.group("ip")] += 1

    suspicious = {
        ip: count for ip, count in failed_by_ip.items() if count >= threshold
    }

    return {
        "total_events": total_events,
        "failed_logins": sum(failed_by_ip.values()),
        "successful_logins": sum(successful_by_ip.values()),
        "unique_source_ips": len(set(failed_by_ip) | set(successful_by_ip)),
        "failed_by_ip": dict(failed_by_ip),
        "successful_by_ip": dict(successful_by_ip),
        "suspicious_ips": suspicious,
        "threshold": threshold,
    }


def print_report(result: dict, log_path: str | Path) -> None:
    """Print a SOC-oriented report to stdout."""
    print("=== Mini SOC Log Analyzer ===")
    print()
    print(f"Log file: {log_path}")
    print(f"Total events: {result['total_events']}")
    print(f"Failed logins: {result['failed_logins']}")
    print(f"Successful logins: {result['successful_logins']}")
    print(f"Unique source IPs: {result['unique_source_ips']}")
    print()

    print("Suspicious IPs:")
    if result["suspicious_ips"]:
        for ip, count in sorted(
            result["suspicious_ips"].items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print(f"- {ip}: {count} failed attempts [HIGH]")
    else:
        print("- None detected")

    print()
    if result["suspicious_ips"]:
        print("Potential detection:")
        print("T1110 - Brute Force")
    else:
        print("Potential detection:")
        print("No brute-force threshold exceeded")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious login activity."
    )
    parser.add_argument("log_file", help="Path to an SSH-style authentication log")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts required to flag an IP (default: 5)",
    )
    args = parser.parse_args()

    result = analyze_log(args.log_file, args.threshold)
    print_report(result, args.log_file)


if __name__ == "__main__":
    main()
