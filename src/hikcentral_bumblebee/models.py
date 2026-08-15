"""Dataclasses for HikCentral Bumblebee API."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Area:
    id: str
    name: str
    parent_id: str | None = None


@dataclass
class DoorElement:
    id: str
    name: str
    online: bool = False
    magnet_state: int | None = None
    lock_state: int | None = None
    policy_state: int | None = None
    overall_status: int | None = None
    controller_id: str | None = None
    controller_address: str | None = None
    door_no: int | None = None
    associated_cameras: list[str] = field(default_factory=list)


@dataclass
class CameraElement:
    id: str
    name: str
    address: str | None = None
    username: str | None = None
    password: str | None = None


@dataclass
class AccessController:
    id: str
    name: str
    address: str | None = None
    username: str | None = None
    password: str | None = None


@dataclass
class VideoIntercom:
    id: str
    name: str
