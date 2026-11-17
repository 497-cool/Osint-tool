#!/usr/bin/env python3
"""Collecte quelques informations publiques sur un nom de domaine."""

import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request


def normalize_domain(value: str) -> str:
    # Accepte un nom de domaine, pas une URL ou une adresse IP.
    domain = value.strip().lower().rstrip(".")
    if "://" in domain or "/" in domain or ":" in domain:
        raise ValueError("Saisis un nom de domaine, sans URL ni chemin.")

    domain = domain.encode("idna").decode("ascii")
    if len(domain) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
        domain,
    ):
        raise ValueError("Nom de domaine invalide.")

    return domain


def dns_lookup(domain: str) -> list[str]:
    try:
        results = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        return sorted({result[4][0] for result in results})
    except socket.gaierror:
        return []


def rdap_lookup(domain: str) -> dict:
    url = f"https://rdap.org/domain/{urllib.parse.quote(domain, safe='.-')}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "basic-osint/1.0", "Accept": "application/rdap+json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return {}


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage : python {sys.argv[0]} exemple.com")
        raise SystemExit(2)

    try:
        domain = normalize_domain(sys.argv[1])
    except (ValueError, UnicodeError) as error:
        print(f"Erreur : {error}")
        raise SystemExit(2)

    ips = dns_lookup(domain)
    data = rdap_lookup(domain)

    nameservers = sorted({
        item.get("ldhName", "")
        for item in data.get("nameservers", [])
        if item.get("ldhName")
    })
    events = [
        {"événement": event.get("eventAction"), "date": event.get("eventDate")}
        for event in data.get("events", [])
        if event.get("eventAction") and event.get("eventDate")
    ]

    print(f"Domaine : {domain}")
    print(f"Adresses IP : {', '.join(ips) if ips else 'aucune trouvée'}")
    print(f"Serveurs DNS : {', '.join(nameservers) if nameservers else 'non disponibles'}")
    print("Événements RDAP :", json.dumps(events, ensure_ascii=False) if events else "non disponibles")


if __name__ == "__main__":
    main()
