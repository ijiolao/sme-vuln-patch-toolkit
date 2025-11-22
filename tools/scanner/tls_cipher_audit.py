#!/usr/bin/env python3
"""
tls_cipher_audit.py

Simple TLS audit helper for SMEs.

- Connects to one or more host:port targets
- Reports:
    * Negotiated TLS version
    * Negotiated cipher suite
    * Key length (if available)
    * Flags weak protocols and weak ciphers based on a simple ruleset

This is NOT a full replacement for tools like ssllabs, sslscan, or testssl.sh,
but it gives a quick low-cost view useful for your TLS & Misconfiguration Baseline.

Usage examples:
    python tls_cipher_audit.py --target example.com:443
    python tls_cipher_audit.py --targets example.com:443,api.example.com:443
    python tls_cipher_audit.py --input targets.txt --output tls_report.csv

Input file format (one target per line):
    example.com:443
    api.example.com:443
    10.0.0.10:8443
"""

import argparse
import csv
import socket
import ssl
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional


@dataclass
class TLSResult:
    target: str
    hostname: str
    port: int
    tls_version: Optional[str]
    cipher_name: Optional[str]
    cipher_protocol: Optional[str]
    cipher_bits: Optional[int]
    weak_protocol: bool
    weak_cipher: bool
    error: Optional[str]


# Weak protocol versions (if we ever see them)
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Simple weak cipher matchers (substring checks)
WEAK_CIPHER_SUBSTRINGS = [
    "RC4",
    "3DES",
    "DES-",
    "MD5",
    "NULL",
    "EXPORT",
]


def parse_target(target: str) -> TLSResult:
    """
    Parse host:port string and return a TLSResult shell with no data yet.
    """
    target = target.strip()
    if not target:
        raise ValueError("Empty target entry")

    if ":" not in target:
        host = target
        port = 443
    else:
        host, port_str = target.rsplit(":", 1)
        if not port_str.isdigit():
            raise ValueError(f"Invalid port in target: {target}")
        port = int(port_str)

    return TLSResult(
        target=target,
        hostname=host,
        port=port,
        tls_version=None,
        cipher_name=None,
        cipher_protocol=None,
        cipher_bits=None,
        weak_protocol=False,
        weak_cipher=False,
        error=None,
    )


def is_weak_protocol(tls_version: Optional[str]) -> bool:
    if not tls_version:
        return False
    return tls_version in WEAK_PROTOCOLS


def is_weak_cipher(cipher_name: Optional[str], cipher_bits: Optional[int]) -> bool:
    if not cipher_name:
        return False

    # Check for obviously weak algorithms by name
    upper_name = cipher_name.upper()
    for bad in WEAK_CIPHER_SUBSTRINGS:
        if bad in upper_name:
            return True

    # Check key length if available
    if cipher_bits is not None and cipher_bits < 128:
        return True

    return False


def check_target(t: TLSResult, timeout: float = 5.0) -> TLSResult:
    """
    Perform a single TLS connection to the target and record negotiated details.
    """
    context = ssl.create_default_context()
    # Enforce minimum TLS 1.2 (modern baseline)
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        with socket.create_connection((t.hostname, t.port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=t.hostname) as ssock:
                # protocol version string is available on modern Python
                try:
                    t.tls_version = ssock.version()
                except Exception:
                    t.tls_version = None

                cipher = ssock.cipher()
                # cipher() returns (cipher_name, protocol, secret_bits)
                if cipher:
                    t.cipher_name = cipher[0]
                    t.cipher_protocol = cipher[1]
                    t.cipher_bits = cipher[2]

                t.weak_protocol = is_weak_protocol(t.tls_version)
                t.weak_cipher = is_weak_cipher(t.cipher_name, t.cipher_bits)

    except Exception as e:
        t.error = str(e)

    return t


def load_targets_from_file(path: Path) -> List[str]:
    targets: List[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Quick TLS cipher audit for one or more host:port targets."
    )
    parser.add_argument(
        "--target",
        help="Single target in host:port format (default port 443 if omitted).",
    )
    parser.add_argument(
        "--targets",
        help="Comma-separated list of targets in host:port format.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Path to a text file with one host:port per line.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path to write CSV output. If omitted, only console output is shown.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Socket timeout in seconds (default: 5.0).",
    )
    return parser.parse_args()


def gather_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = []

    if args.target:
        targets.append(args.target)

    if args.targets:
        for t in args.targets.split(","):
            t = t.strip()
            if t:
                targets.append(t)

    if args.input:
        if not args.input.exists():
            raise FileNotFoundError(f"Input file not found: {args.input}")
        from_file = load_targets_from_file(args.input)
        targets.extend(from_file)

    # Remove duplicates while preserving order
    seen = set()
    unique_targets: List[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)

    if not unique_targets:
        raise ValueError("No targets specified. Use --target, --targets, or --input.")

    return unique_targets


def print_console(results: List[TLSResult]) -> None:
    print("TLS Cipher Audit Results")
    print("------------------------")
    for r in results:
        if r.error:
            print(f"[{r.target}] ERROR: {r.error}")
            continue

        flags = []
        if r.weak_protocol:
            flags.append("WEAK_PROTOCOL")
        if r.weak_cipher:
            flags.append("WEAK_CIPHER")

        flag_str = ", ".join(flags) if flags else "OK"

        print(
            f"[{r.target}] TLS={r.tls_version or 'N/A'} "
            f"Cipher={r.cipher_name or 'N/A'} "
            f"Bits={r.cipher_bits or 'N/A'} "
            f"-> {flag_str}"
        )


def write_csv(results: List[TLSResult], path: Path) -> None:
    fieldnames = [
        "target",
        "hostname",
        "port",
        "tls_version",
        "cipher_name",
        "cipher_protocol",
        "cipher_bits",
        "weak_protocol",
        "weak_cipher",
        "error",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))


def main() -> int:
    args = parse_args()

    try:
        targets = gather_targets(args)
    except Exception as e:
        print(f"Error: {e}")
        return 1

    results: List[TLSResult] = []

    for t_str in targets:
        try:
            t = parse_target(t_str)
        except Exception as e:
            # Store parse error as result
            results.append(
                TLSResult(
                    target=t_str,
                    hostname=t_str,
                    port=0,
                    tls_version=None,
                    cipher_name=None,
                    cipher_protocol=None,
                    cipher_bits=None,
                    weak_protocol=False,
                    weak_cipher=False,
                    error=f"Invalid target format: {e}",
                )
            )
            continue

        r = check_target(t, timeout=args.timeout)
        results.append(r)

    print_console(results)

    if args.output:
        write_csv(results, args.output)
        print(f"\nCSV report written to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
