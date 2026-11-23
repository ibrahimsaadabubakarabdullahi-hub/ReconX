
#!/usr/bin/env python3
"""
ReconX - Portable Reconnaissance Toolkit
For authorised security assessments only.
Compatible with Linux and Termux.
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

APP = "ReconX"
VERSION = "0.1"
USER_AGENT = "ReconX/0.1"
DEFAULT_TIMEOUT = 8


def timestamp():
    return datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()


def validate_host(value):
    value = value.strip()

    if not value or any(c in value for c in "/?#@ "):
        raise ValueError("Enter a hostname or IP, not a URL.")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()

        if len(host) > 253 or "." not in host:
            raise ValueError("Invalid hostname.")

        for label in host.split("."):
            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(c.isalnum() or c == "-" for c in label)
            ):
                raise ValueError("Invalid hostname.")

        return host


def authorization(scope):
    print("\n================================")
    print("       RECONX AUTHORIZATION")
    print("================================")
    print("Target:", scope)
    print("Only assess systems you own or")
    print("have explicit permission to test.\n")

    answer = input("Are you authorized? [y/N]: ")

    if answer.lower() not in ("y", "yes"):
        sys.exit("Scan cancelled.")


def resolve_dns(host):
    try:
        return sorted({
            item[4][0]
            for item in socket.getaddrinfo(host, None)
        })
    except socket.gaierror as error:
        return [str(error)]


def save_report(data, output=None, fmt="json"):
    Path("reports").mkdir(exist_ok=True)

    if output:
        path = Path(output)
    else:
        stamp = datetime.datetime.now().strftime(
            "%Y%m%d-%H%M%S"
        )
        path = Path("reports") / f"reconx-{stamp}.{fmt}"

    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        path.write_text(
            json.dumps(data, indent=4),
            encoding="utf-8"
        )

    elif fmt == "html":
        rows = ""

        for key, value in data.items():
            rows += (
                "<tr><th>"
                + html.escape(str(key))
                + "</th><td><pre>"
                + html.escape(json.dumps(value, indent=2))
                + "</pre></td></tr>"
            )

        document = f"""
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="UTF-8">
        <title>ReconX Report</title>
        <style>
        body {{
            font-family: Arial;
            margin: 30px;
            background: #111827;
            color: white;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        td, th {{
            border: 1px solid #555;
            padding: 12px;
            text-align: left;
        }}
        pre {{ white-space: pre-wrap; }}
        </style>
        </head>
        <body>
        <h1>ReconX Security Report</h1>
        <table>{rows}</table>
        </body>
        </html>
        """

        path.write_text(document, encoding="utf-8")

    return path


def web_scan(args):
    host = validate_host(args.target)

    port = args.port or (
        443 if args.scheme == "https" else 80
    )

    url = f"{args.scheme}://{host}:{port}/"

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
        headers={"User-Agent": USER_AGENT},
        method="GET"
    )

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(
            context=ssl.create_default_context()
        )
    )

    try:
        with opener.open(
            request,
            timeout=args.timeout
        ) as response:

            result["http"] = {
                "status": response.status,
                "final_url": response.geturl(),
                "headers": dict(response.headers.items())
            }

    except urllib.error.HTTPError as error:
        result["http"] = {
            "status": error.code,
            "headers": dict(error.headers.items())
        }

    except Exception as error:
        result["http_error"] = str(error)

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

        except Exception as error:
            result["tls_error"] = str(error)

    return result


def port_scan(args):
    host = validate_host(args.target)

    nmap = shutil.which("nmap")

    if not nmap:
        raise RuntimeError(
            "Nmap missing. Install it using your package manager."
        )

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
        "-",
        host
    ]

    if args.ports:
        command[1:1] = ["-p", args.ports]
    else:
        command[1:1] = ["--top-ports", "100"]

    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=args.timeout + 20
    )

    if process.returncode not in (0, 1):
        raise RuntimeError(process.stderr)

    root = ET.fromstring(process.stdout)

    ports = []

    for item in root.findall(".//port"):
        state = item.find("state")
        service = item.find("service")

        ports.append({
            "protocol": item.get("protocol"),
            "port": item.get("portid"),
            "state": (
                state.get("state")
                if state is not None else "unknown"
            ),
            "service": (
                service.get("name")
                if service is not None else None
            ),
            "product": (
                service.get("product")
                if service is not None else None
            ),
            "version": (
                service.get("version")
                if service is not None else None
            )
        })

    return {
        "tool": APP,
        "version": VERSION,
        "timestamp": timestamp(),
        "module": "ports",
        "target": host,
        "ports": ports
    }


def local_scan(args):
    network = ipaddress.ip_network(
        args.network,
        strict=False
    )

    if not network.is_private:
        raise ValueError(
            "Only private network ranges are supported."
        )

    if network.num_addresses > 256:
        raise ValueError(
            "Maximum supported network size is /24."
        )

    nmap = shutil.which("nmap")

    if not nmap:
        raise RuntimeError("Nmap is required.")

    command = [
        nmap,
        "-sn",
        "-T3",
        "--max-retries",
        "1",
        "-oX",
        "-",
        str(network)
    ]

    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=args.timeout + 20
    )

    if process.returncode not in (0, 1):
        raise RuntimeError(process.stderr)

    root = ET.fromstring(process.stdout)
    hosts = []

    for host in root.findall("host"):
        status = host.find("status")

        if status is None or status.get("state") != "up":
            continue

        addresses = [
            {
                "type": address.get("addrtype"),
                "address": address.get("addr")
            }
            for address in host.findall("address")
        ]

        hosts.append({"addresses": addresses})

    return {
        "tool": APP,
        "version": VERSION,
        "timestamp": timestamp(),
        "module": "local",
        "network": str(network),
        "hosts": hosts,
        "count": len(hosts)
    }


def create_parser():
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - Portable Reconnaissance Toolkit"
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
    web.add_argument("--port", type=int)
    web.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    web.add_argument(
        "--format",
        choices=["json", "html"],
        default="json"
    )
    web.add_argument("-o", "--output")
    web.set_defaults(function=web_scan)

    ports = modules.add_parser(
        "ports",
        help="Conservative Nmap TCP discovery"
    )

    ports.add_argument("target")
    ports.add_argument("--ports")
    ports.add_argument("--timeout", type=int, default=60)
    ports.add_argument(
        "--format",
        choices=["json", "html"],
        default="json"
    )
    ports.add_argument("-o", "--output")
    ports.set_defaults(function=port_scan)

    local = modules.add_parser(
        "local",
        help="Private local-network discovery"
    )

    local.add_argument("network")
    local.add_argument("--timeout", type=int, default=60)
    local.add_argument(
        "--format",
        choices=["json", "html"],
        default="json"
    )
    local.add_argument("-o", "--output")
    local.set_defaults(function=local_scan)

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.timeout < 1:
        parser.error("Timeout must be at least 1 second.")

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

        print("\nReconX completed.")
        print("Report saved:", report)

        if args.module == "ports":
            for port in data["ports"]:
                print(
                    f'{port["port"]}/{port["protocol"]} '
                    f'{port["state"]} '
                    f'{port["service"] or ""}'
                )

        if args.module == "local":
            print("Live devices:", data["count"])

    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(130)

    except (
        ValueError,
        RuntimeError,
        subprocess.TimeoutExpired
    ) as error:
        sys.exit(f"ReconX error: {error}")


if __name__ == "__main__":
    main()
