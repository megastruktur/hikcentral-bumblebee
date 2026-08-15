#!/usr/bin/env python3
"""List all doors and their statuses.

Usage:
    export HIK_URL="https://your-hikcentral-host:443"
    export HIK_USER="your_username"
    export HIK_PASS="your_password"
    python examples/list_doors.py
"""

from __future__ import annotations

import os

from hikcentral_bumblebee import BumblebeeClient


def main() -> None:
    url = os.environ.get("HIK_URL")
    user = os.environ.get("HIK_USER")
    password = os.environ.get("HIK_PASS")

    if not all([url, user, password]):
        raise SystemExit("Set HIK_URL, HIK_USER, HIK_PASS env vars first.")

    cli = BumblebeeClient(url, user, password)
    cli.login()
    print("Logged in.\n")

    areas = cli.get_areas()
    if areas:
        print(f"Areas ({len(areas)}):")
        for a in areas:
            print(f"  [{a.id}] {a.name}  (parent={a.parent_id})")
        print()

    doors = cli.get_door_elements()
    print(f"Doors ({len(doors)}):")
    for door in doors:
        detail = cli.get_door(door.id)
        status = _format_status(detail)
        print(f"  [{detail.id}] {detail.name}  online={detail.online}  {status}")


def _format_status(door) -> str:
    states = []
    if door.magnet_state is not None:
        states.append(f"magnet={door.magnet_state}")
    if door.lock_state is not None:
        states.append(f"lock={door.lock_state}")
    if door.policy_state is not None:
        states.append(f"policy={door.policy_state}")
    if door.overall_status is not None:
        states.append(f"overall={door.overall_status}")
    if door.controller_address:
        states.append(f"ctrl={door.controller_address}")
    return "  ".join(states) if states else "(no status)"


if __name__ == "__main__":
    main()
