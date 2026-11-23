
#!/usr/bin/env python3
"""
ReconX - Portable Reconnaissance Toolkit
Version 0.2

For authorised security assessments only.
Compatible with Linux and Android Termux.
Requires Python 3.10+.
"""

import argparse
import datetime
import html
import ipaddress
import json
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from pathlib import Path
from urllib.parse import urlsplit

APP = "ReconX"
VERSION = "0.2"
USER_AGENT = "ReconX/0.2"
DEFAULT_TIMEOUT = 8
MAX_PORT_SELECTION = 100


# ==========================================
# GENERAL UTILITIES
# ==========================================

def timestamp():
    return datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()


def validate_timeout(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValueError("Timeout must be an integer.")

    if not 1 <= value <= 300:
        raise ValueError("Timeout must be between 1 and 300 seconds.")

    return value


def validate_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(
            "Port must be a number."
        )

    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(
            "Port must be between 1 and 65535."
        )

    return port


def validate_host(value):
    value = value.strip()

    if not value or any(
        char in value for char in "/?#@ \t\r\n"
    ):
        raise ValueError(
            "Enter a hostname or IP address, not a URL."
        )

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    try:
        host = (
            value.rstrip(".")
            .encode("idna")
            .decode("ascii")
            .lower()
        )
    except UnicodeError:
        raise ValueError("Invalid hostname.")

    if not host or len(host) > 253 or "." not in host:
        raise ValueError("Invalid hostname.")

    for label in host.split("."):
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(
                char.isalnum() or char == "-"
                for char in label
            )
        ):
            raise ValueError("Invalid hostname.")

    return host


def validate_ports(value):
    """
    Accept numeric TCP ports and ranges.
    Maximum selection: 100 unique ports.
    """

    selected = set()

    for part in value.split(","):
        part = part.strip()

        if not part:
            raise ValueError("Invalid port selection.")

        if "-" in part:
            pieces = part.split("-")

            if len(pieces) != 2:
                raise ValueError("Invalid port range.")

            try:
                start, end = map(int, pieces)
            except ValueError:
                raise ValueError("Ports must be numeric.")

            if not (
                1 <= start <= 65535
                and 1 <= end <= 65535
                and start <= end
            ):
                raise ValueError("Invalid port range.")

            selected.update(range(start, end + 1))

        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError("Ports must be numeric.")

            if not 1 <= port <= 65535:
                raise ValueError(
                    "Ports must be between 1 and 65535."
                )

            selected.add(port)

        if len(selected) > MAX_PORT_SELECTION:
            raise ValueError(
                "Maximum selection is 100 unique ports."
            )

    if not selected:
        raise ValueError("No ports selected.")

    return ",".join(
        str(port) for port in sorted(selected)
    )


# ==========================================
# AUTHORISATION
# ==========================================

def authorization(scope):
    print("\n================================")
    print("       RECONX AUTHORIZATION")
    print("================================")
    print("Target:", scope)
    print()
    print("Only assess systems you own or")
    print("have explicit permission to test.")
    print()

    answer = input(
        "Are you authorized? [y/N]: "
    ).strip().lower()

    if answer not in ("y", "yes"):
        sys.exit("Scan cancelled.")


# ==========================================
# DNS
# ==========================================

def resolve_dns(host):
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                host,
                None,
                type=socket.SOCK_STREAM
            )
        }

        return sorted(addresses)

    except socket.gaierror as error:
        return []


# ==========================================
# REPORT GENERATION
# ==========================================

def save_report(data, output=None, fmt="json"):

    if output:
        path = Path(output)
    else:
        Path("reports").mkdir(
            parents=True,
            exist_ok=True
        )

        stamp = datetime.datetime.now().strftime(
            "%Y%m%d-%H%M%S"
        )

        path = (
            Path("reports")
            / f"reconx-{stamp}.{fmt}"
        )

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if fmt == "json":
        path.write_text(
            json.dumps(data, indent=4),
            encoding="utf-8"
        )

    elif fmt == "html":
        rows = ""

        for key, value in data.items():
            formatted = json.dumps(
                value,
                indent=2,
                ensure_ascii=False
            )

            rows += (
                "<tr><th>"
                + html.escape(str(key))
                + "</th><td><pre>"
                + html.escape(formatted)
                + "</pre></td></tr>"
            )

        document = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconX Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 25px;
    background: #111827;
    color: white;
}}
h1 {{ color: #38bdf8; }}
table {{
    width: 100%;
    border-collapse: collapse;
}}
td, th {{
    border: 1px solid #475569;
    padding: 12px;
    text-align: left;
    vertical-align: top;
}}
th {{ width: 180px; }}
pre {{
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}}
</style>
</head>
<body>
<h1>ReconX Security Report</h1>
<p>Version {VERSION}</p>
<table>{rows}</table>
</body>
</html>
"""

        path.write_text(
            document,
            encoding="utf-8"
        )

    return path


# ==========================================
# WEB RECONNAISSANCE
# ==========================================

def web_scan(args):

    host = validate_host(args.target)

    port = args.port or (
        443 if args.scheme == "https" else 80
    )

    url_host = (
        f"[{host}]" if ":" in host else host
    )

    url = (
        f"{args.scheme}://{url_host}:{port}/"
    )

    result = {
        "tool": APP,
        "version": VERSION,
        "timestamp": timestamp(),
        "module": "web",
        "target": host,
        "url": url,
        "dns": resolve_dns(host)
    }

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*"
        },
        method="GET"
    )

    opener = urllib.request.build_opener()

    try:
        with opener.open(
            request,
            timeout=args.timeout
        ) as response:

            result["http"] = {
                "status": response.status,
                "final_url": response.geturl(),
                "headers": dict(
                    response.headers.items()
                )
            }

    except urllib.error.HTTPError as error:
        result["http"] = {
            "status": error.code,
            "final_url": error.geturl(),
            "headers": dict(
                error.headers.items()
            )
        }

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        ValueError
    ) as error:
        result["http_error"] = str(error)

    # HTTPS certificate and connection information

    if args.scheme == "https":

        try:
            context = ssl.create_default_context()

            with socket.create_connection(
                (host, port),
                timeout=args.timeout
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=host
                ) as tls:

                    cert = tls.getpeercert()

                    result["tls"] = {
                        "version": tls.version(),
                        "cipher": tls.cipher(),
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "valid_from": cert.get("notBefore"),
                        "valid_until": cert.get("notAfter")
                    }

        except (
            ssl.SSLError,
            OSError,
            TimeoutError,
            ValueError
        ) as error:
            result["tls_error"] = str(error)

    return result


# ==========================================
# NMAP UTILITIES
# ==========================================

def get_nmap():

    nmap = shutil.which("nmap")

    if not nmap:
        raise RuntimeError(
            "Nmap is missing. Install it first."
        )

    return nmap


def run_nmap(command, timeout):

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "Nmap exceeded its allowed execution time."
        )

    if process.returncode != 0:
        message = (
            process.stderr.strip()
            or process.stdout.strip()
            or "Unknown Nmap error."
        )

        raise RuntimeError(
            f"Nmap failed: {message}"
        )

    if not process.stdout.strip():
        raise RuntimeError(
            "Nmap returned an empty report."
        )

    try:
        return ET.fromstring(process.stdout)

    except ET.ParseError:
        raise RuntimeError(
            "Could not read Nmap XML output."
        )


# ==========================================
# TCP PORT DISCOVERY
# ==========================================

def port_scan(args):

    host = validate_host(args.target)
    nmap = get_nmap()

    command = [
        nmap,
        "-sT",
        "-sV",
        "--version-light",
        "-T3",
        "--max-retries",
        "1",
        "--host-timeout",
        f"{args.timeout}s",
        "-oX",
        "-"
    ]

    if args.ports:
        command.extend([
            "-p",
            validate_ports(args.ports)
        ])
    else:
        command.extend([
            "--top-ports",
            "100"
        ])

    command.extend([
        "--",
        host
    ])

    root = run_nmap(
        command,
        args.timeout + 30
    )

    ports = []

    for item in root.findall(".//port"):

        state = item.find("state")
        service = item.find("service")

        ports.append({
            "protocol": item.get("protocol"),
            "port": item.get("portid"),
            "state": (
                state.get("state")
                if state is not None
                else "unknown"
            ),
            "service": (
                service.get("name")
                if service is not None
                else None
            ),
            "product": (
                service.get("product")
                if service is not None
                else None
            ),
            "version": (
                service.get("version")
                if service is not None
                else None
            )
        })

    return {
        "tool": APP,
        "version": VERSION,
        "timestamp": timestamp(),
        "module": "ports",
        "target": host,
        "ports_scanned": (
            validate_ports(args.ports)
            if args.ports
            else "Top 100 ports"
        ),
        "ports": ports,
        "count": len(ports)
    }


# ==========================================
# LOCAL NETWORK DISCOVERY
# ==========================================

def local_scan(args):

    try:
        network = ipaddress.ip_network(
            args.network,
            strict=False
        )
    except ValueError:
        raise ValueError(
            "Enter a valid IPv4 network CIDR."
        )

    if not isinstance(
        network,
        ipaddress.IPv4Network
    ):
        raise ValueError(
            "Only IPv4 local networks are supported."
        )

    private_ranges = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16")
    ]

    if not any(
        network.subnet_of(private)
        for private in private_ranges
    ):
        raise ValueError(
            "Only RFC1918 private IPv4 networks are supported."
        )

    if network.num_addresses > 256:
        raise ValueError(
            "Maximum supported network size is /24."
        )

    nmap = get_nmap()

    command = [
        nmap,
        "-sn",
        "-T3",
        "--max-retries",
        "1",
        "-oX",
        "-",
        "--",
        str(network)
    ]

    root = run_nmap(
        command,
        args.timeout + 30
    )

    hosts = []

    for host in root.findall("host"):

        status = host.find("status")

        if (
            status is None
            or status.get("state") != "up"
        ):
            continue

        addresses = [
            {
                "type": address.get("addrtype"),
                "address": address.get("addr")
            }
            for address in host.findall("address")
        ]

        hostnames = [
            item.get("name")
            for item in host.findall(
                "hostnames/hostname"
            )
            if item.get("name")
        ]

        hosts.append({
            "addresses": addresses,
            "hostnames": hostnames
        })

    return {
        "tool": APP,
        "version": VERSION,
        "timestamp": timestamp(),
        "module": "local",
        "network": str(network),
        "hosts": hosts,
        "count": len(hosts)
    }


# ==========================================
# COMMAND-LINE INTERFACE
# ==========================================

def create_parser():

    parser = argparse.ArgumentParser(
        prog="reconx",
        description=(
            "ReconX - Portable Reconnaissance Toolkit"
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP} {VERSION}"
    )

    modules = parser.add_subparsers(
        dest="module",
        required=True
    )

    # WEB MODULE

    web = modules.add_parser(
        "web",
        help="HTTP, HTTPS, DNS and TLS inspection"
    )

    web.add_argument("target")

    web.add_argument(
        "--scheme",
        choices=["http", "https"],
        default="https"
    )

    web.add_argument(
        "--port",
        type=validate_port
    )

    web.add_argument(
        "--timeout",
        type=validate_timeout,
        default=DEFAULT_TIMEOUT
    )

    web.add_argument(
        "--format",
        choices=["json", "html"],
        default="json"
    )

    web.add_argument(
        "-o",
        "--output"
    )

    web.set_defaults(function=web_scan)

    # PORT MODULE

    ports = modules.add_parser(
        "ports",
        help="Conservative Nmap TCP discovery"
    )

    ports.add_argument("target")

    ports.add_argument(
        "--ports",
        help="Select up to 100 TCP ports, e.g. 22,80,443"
    )

    ports.add_argument(
        "--timeout",
        type=validate_timeout,
        default=60
    )

    ports.add_argument(
        "--format",
        choices=["json", "html"],
        default="json"
    )

    ports.add_argument(
        "-o",
        "--output"
    )

    ports.set_defaults(function=port_scan)

    # LOCAL MODULE

    local = modules.add_parser(
        "local",
        help="Private local IPv4 network discovery"
    )

    local.add_argument("network")

    local.add_argument(
        "--timeout",
        type=validate_timeout,
        default=60
    )

    local.add_argument(
        "--format",
        choices=["json", "html"],
        default="json"
    )

    local.add_argument(
        "-o",
        "--output"
    )

    local.set_defaults(function=local_scan)

    return parser


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():

    parser = create_parser()
    args = parser.parse_args()

    scope = getattr(
        args,
        "target",
        getattr(args, "network", "")
    )

    try:

        authorization(scope)

        data = args.function(args)

        report = save_report(
            data,
            args.output,
            args.format
        )

        print("\n================================")
        print("       RECONX COMPLETED")
        print("================================")

        print("Version:", VERSION)
        print("Module:", args.module)
        print("Report saved:", report)

        if args.module == "ports":

            print("\nDiscovered TCP ports:")

            for port in data["ports"]:

                print(
                    f'{port["port"]}/'
                    f'{port["protocol"]} '
                    f'{port["state"]} '
                    f'{port["service"] or ""}'
                )

            print(
                "\nTotal port entries:",
                data["count"]
            )

        elif args.module == "local":

            print(
                "\nLive devices:",
                data["count"]
            )

        elif args.module == "web":

            print(
                "\nHTTP status:",
                data.get("http", {}).get(
                    "status",
                    "Unavailable"
                )
            )

            print(
                "DNS addresses:",
                data["dns"]
            )

    except KeyboardInterrupt:

        print("\nScan interrupted.")
        sys.exit(130)

    except (
        ValueError,
        RuntimeError,
        OSError
    ) as error:

        sys.exit(
            f"ReconX error: {error}"
        )


if __name__ == "__main__":
    main()
