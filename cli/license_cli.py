import argparse
import json
import os
import sys
from urllib.parse import quote

import requests

ADMIN_HEADER = "X-Admin-Token"


def _base_url(server: str) -> str:
    return server.rstrip("/")


def _admin_token(value: str | None) -> str:
    token = value or os.getenv("LICENSE_ADMIN_TOKEN")
    if not token:
        raise SystemExit("Admin token missing. Set --admin-token or LICENSE_ADMIN_TOKEN")
    return token


def _print_response(resp: requests.Response) -> None:
    try:
        payload = resp.json()
    except ValueError:
        payload = {"raw": resp.text}

    if resp.status_code >= 400:
        print(json.dumps({"status_code": resp.status_code, "error": payload}, indent=2))
        raise SystemExit(1)

    print(json.dumps(payload, indent=2))


def generate_license(args: argparse.Namespace) -> None:
    token = _admin_token(args.admin_token)
    payload = {
        "product": args.product,
        "max_devices": args.devices,
        "expiration_date": args.expires,
    }
    resp = requests.post(
        f"{_base_url(args.server)}/generate",
        json=payload,
        headers={ADMIN_HEADER: token},
        timeout=20,
    )
    _print_response(resp)


def revoke_license(args: argparse.Namespace) -> None:
    token = _admin_token(args.admin_token)
    payload = {"license_key": args.key}
    resp = requests.post(
        f"{_base_url(args.server)}/revoke",
        json=payload,
        headers={ADMIN_HEADER: token},
        timeout=20,
    )
    _print_response(resp)


def list_activations(args: argparse.Namespace) -> None:
    token = _admin_token(args.admin_token)
    encoded_key = quote(args.key, safe="")
    resp = requests.get(
        f"{_base_url(args.server)}/license/{encoded_key}",
        headers={ADMIN_HEADER: token},
        timeout=20,
    )
    _print_response(resp)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Developer CLI for license management")
    parser.add_argument(
        "--server",
        default=os.getenv("LICENSE_SERVER_URL", "https://YOUR_REAL_LICENSE_API_URL"),
        help="License server base URL",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate-license", help="Create a new license")
    p_gen.add_argument("--devices", type=int, required=True, help="Maximum allowed devices")
    p_gen.add_argument("--product", required=True, help="Product name")
    p_gen.add_argument("--expires", default=None, help="Expiration date YYYY-MM-DD")
    p_gen.add_argument("--admin-token", default=None, help="Admin token")
    p_gen.set_defaults(func=generate_license)

    p_rev = sub.add_parser("revoke-license", help="Revoke an existing license")
    p_rev.add_argument("--key", required=True, help="License key XXXX-XXXX-XXXX-XXXX")
    p_rev.add_argument("--admin-token", default=None, help="Admin token")
    p_rev.set_defaults(func=revoke_license)

    p_list = sub.add_parser("list-activations", help="Show all activations for a key")
    p_list.add_argument("--key", required=True, help="License key XXXX-XXXX-XXXX-XXXX")
    p_list.add_argument("--admin-token", default=None, help="Admin token")
    p_list.set_defaults(func=list_activations)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
