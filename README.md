
# ReconX

**Portable Network & Web Reconnaissance Toolkit**

ReconX is a command-line reconnaissance tool designed for Linux and Android Termux.

## Features

- HTTP and HTTPS inspection
- DNS resolution
- TLS certificate information
- TCP port discovery
- Service identification
- Private local-network discovery
- JSON reports
- HTML reports
- Python command-line interface

## Requirements

- Python 3.10 or newer
- Nmap for port and local-network discovery

## Installation on Termux

```bash
pkg update
pkg install python git nmap

git clone https://github.com/ibrahimsaadabubakarabdullahi-hub/ReconX.git

cd ReconX

python -m pip install .

reconx --help
```

## Installation on Linux

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv git nmap

git clone https://github.com/ibrahimsaadabubakarabdullahi-hub/ReconX.git

cd ReconX

python3 -m venv .venv
source .venv/bin/activate

python -m pip install .

reconx --help
```

## Commands

### Web inspection

```bash
reconx web example.com
```

### HTTP inspection

```bash
reconx web example.com --scheme http
```

### Port discovery

```bash
reconx ports 192.0.2.10
```

### Specific ports

```bash
reconx ports 192.0.2.10 --ports 22,80,443
```

### Local network discovery

```bash
reconx local 192.168.1.0/24
```

## Reports

ReconX supports:

- JSON
- HTML

Reports are stored in the reports directory by default.

## Security Policy

ReconX is intended for authorised security assessments.

Only scan systems and networks you own or have explicit permission to assess.

ReconX does not include denial-of-service attacks, exploitation, password attacks or unauthorised camera access.

## Development Status

ReconX is under active development.

Future modules are planned for:

- Wi-Fi inventory
- Authorised camera-device identification
- Advanced web security inspection

## Supported Platforms

- Android Termux
- Linux

## Project

**ReconX — Private Development Repository**
