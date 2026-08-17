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
    thumbnail_url: str | None = None


@dataclass
class AccessController:
    id: str
    name: str
    address: str | None = None
    username: str | None = None
    password: str | None = None


@dataclass
class VideoIntercomCamera:
    """A door-station camera referenced by a video intercom.

    ``element_id`` is the HikCentral CameraElement id — usable everywhere a
    regular camera element id works (CommonUrl streaming, thumbnails). These
    elements are NOT returned by ``get_camera_elements()``; they are only
    reachable through the video intercom detail.
    """

    element_id: str
    name: str
    online: bool = False


@dataclass
class VideoIntercom:
    id: str
    name: str
    online: bool = False
    #: Door ids controlled by this door station (ACS DoorElement ids).
    door_ids: list[str] = field(default_factory=list)
    #: Door-station cameras (CameraElement ids are NOT in CameraElements list).
    cameras: list[VideoIntercomCamera] = field(default_factory=list)
