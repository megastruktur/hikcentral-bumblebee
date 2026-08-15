"""
RED phase: tests for models dataclasses.
"""

from hikcentral_bumblebee.models import (
    Area,
    DoorElement,
    CameraElement,
    AccessController,
    VideoIntercom,
)


class TestDoorElement:
    def test_door_element_default_values(self):
        """DoorElement has sensible defaults for optional fields."""
        door = DoorElement(id="123", name="Test Door", online=False)
        assert door.id == "123"
        assert door.name == "Test Door"
        assert door.online is False
        assert door.magnet_state is None
        assert door.lock_state is None

    def test_door_element_full_init(self):
        """DoorElement accepts all fields."""
        door = DoorElement(
            id="996",
            name="Kalitka_SP1",
            online=True,
            magnet_state=0,
            lock_state=1,
            policy_state=0,
            overall_status=0,
            controller_id="205",
            controller_address="203.0.113.96",
            door_no=1,
            associated_cameras=["11", "12"],
        )
        assert door.magnet_state == 0
        assert door.lock_state == 1
        assert door.associated_cameras == ["11", "12"]


class TestArea:
    def test_area_basic(self):
        area = Area(id="1", name="Въезды", parent_id="0")
        assert area.id == "1"
        assert area.name == "Въезды"


class TestAccessController:
    def test_access_controller_basic(self):
        ctrl = AccessController(id="205", name="Ctrl_205", address="203.0.113.96")
        assert ctrl.id == "205"
        assert ctrl.name == "Ctrl_205"


class TestCameraElement:
    def test_camera_element_basic(self):
        cam = CameraElement(id="11", name="Camera_Entrance")
        assert cam.id == "11"


class TestVideoIntercom:
    def test_video_intercom_basic(self):
        vi = VideoIntercom(id="1", name="Panel_1")
        assert vi.id == "1"
