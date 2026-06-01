# PyOSINT

A modular tool for OSINT work.

# Installation

Install necessary Python libraries

    pip install aiohttp aiohttp_socks

# Usage

Full passive recon on a domain, write reports

    python pyosint.py example.com -o report

Email investigation with breach check (key via env)

    python3 pyosint.py target@mail.com

IP recon through Shodan, routed over Tor

    python pyosint.py 8.8.8.8 --tor

Username sweep behind a proxy with UA rotation

    python pyosint.py johndoe --proxy http://127.0.0.1:8080


