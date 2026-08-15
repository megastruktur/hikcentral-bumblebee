"""
Tests for discovery API — get_areas, get_door_elements, get_door, etc.

Note: these tests verify the public API contract — that the client returns
correct model objects from API responses. We inject pre-parsed data via
a mocked _call() to isolate the mapping logic from the XML parsing layer
(which is covered by test_append_info.py).
"""

from tests.conftest import FakeResponse


# ------------------------------------------------------------------------------------------------------------------------------------------
# Capture-shaped response data (mirrors real prod responses: {ErrorModule, ErrorCode, Data}, no Response wrapper)
# ------------------------------------------------------------------------------------------------------------------------------------------

AREAS_RESPONSE_DATA = {
    "ErrorModule": "0",
    "ErrorCode": "0",
    "Data": {
        "AreaList": {
            "Area": [
                {"ID": "30", "Name": "ВЪЕЗДЫ (ИНТЕРКОМ)", "ParentAreaID": "-1"},
                {"ID": "93", "Name": "камеры вызывных", "ParentAreaID": "30"},
            ]
        }
    },
}

DOOR_ELEMENTS_RESPONSE_DATA = {
    "ErrorModule": "0",
    "ErrorCode": "0",
    "Data": {
        "DoorElementList": {
            "DoorElement": [
                {"ID": "996", "BaseInfo": {"Name": "Kalitka_SP1", "Online": "1"}},
                {"ID": "997", "BaseInfo": {"Name": "Kalitka_SP17", "Online": "1"}},
                {"ID": "998", "BaseInfo": {"Name": "Kalitka_SP21", "Online": "0"}},
            ]
        }
    },
}

DOOR_DETAIL_RESPONSE_DATA = {
    "ErrorModule": "0",
    "ErrorCode": "0",
    "Data": {
        "DoorElement": {
            "ID": "996",
            "BaseInfo": {"Name": "Kalitka_SP1", "Online": "1"},
            "AccessController": {
                "ID": "205",
                "BaseInfo": {"Address": "203.0.113.96"},
            },
            "Door": {"No": "1"},
            "DoorStatus": {
                "MagnetState": "0",
                "LockState": "1",
                "PolicyState": "0",
                "OverallStatus": "0",
            },
            "AssociatedCameras": {"Camera": {"CameraID": "11"}},
        }
    },
}

CAMERA_ELEMENTS_RESPONSE_DATA = {
    "ErrorModule": "0",
    "ErrorCode": "0",
    "Data": {
        "CameraElementList": {
            "CameraElement": [
                {"ID": "64", "Name": "SP5 30.8"},
                {"ID": "65", "Name": "SP5 30.9"},
            ]
        }
    },
}

ACCESS_CONTROLLERS_RESPONSE_DATA = {
    "ErrorModule": "0",
    "ErrorCode": "0",
    "Data": {
        "AccessControllerList": {
            "AccessController": [
                {"ID": "32", "BaseInfo": {"Alias": "Face_ID", "Address": "203.0.113.1"}},
                {"ID": "36", "BaseInfo": {"Alias": "Velobox MR1-2", "Address": "203.0.113.2"}},
            ]
        }
    },
}

VIDEO_INTERCOMS_RESPONSE_DATA = {
    "ErrorModule": "0",
    "ErrorCode": "0",
    "Data": {
        "VideoIntercomList": {
            "VideoIntercom": [
                {"ID": "30", "BaseInfo": {"Alias": "SP-1 Door Station"}},
            ]
        }
    },
}


class TestGetAreas:
    def test_get_areas_returns_list_of_areas(self, mock_client):
        """get_areas() returns a list of Area objects."""
        cli, _ = mock_client
        cli._call = lambda path, logical="GET", body_obj=None: AREAS_RESPONSE_DATA

        areas = cli.get_areas()
        assert len(areas) == 2
        assert areas[0].name == "ВЪЕЗДЫ (ИНТЕРКОМ)"
        assert areas[0].id == "30"
        assert areas[0].parent_id is None  # ParentAreaID = "-1"
        assert areas[1].name == "камеры вызывных"
        assert areas[1].parent_id == "30"

    def test_get_areas_uses_mt_get(self, mock_client):
        """get_areas() calls POST with MT=GET in URL."""
        cli, mock_http = mock_client
        mock_http.post.return_value = FakeResponse(
            "<Response><Data><AreaList><Area></Area></AreaList></Data></Response>"
        )
        cli.get_areas()

        url = mock_http.post.call_args.args[0]
        assert "MT=GET" in url
        assert "SID=" in url


class TestGetDoorElements:
    def test_get_door_elements_returns_door_element_list(self, mock_client):
        """get_door_elements() returns list of DoorElement objects."""
        cli, _ = mock_client
        cli._call = lambda path, logical="GET", body_obj=None: DOOR_ELEMENTS_RESPONSE_DATA

        doors = cli.get_door_elements()
        assert len(doors) == 3
        assert doors[0].id == "996"
        assert doors[0].name == "Kalitka_SP1"
        assert doors[0].online is True
        assert doors[2].online is False

    def test_get_door_elements_with_area_id(self, mock_client):
        """get_door_elements(area_id) sends AreaID in body."""
        cli, mock_http = mock_client
        mock_http.post.return_value = FakeResponse(
            "<Response><Data><DoorElementList><DoorElement></DoorElement></DoorElementList></Data></Response>"
        )
        cli.get_door_elements(area_id=5)

        body = mock_http.post.call_args.kwargs.get("content", b"").decode()
        assert "AreaID" in body


class TestGetDoor:
    def test_get_door_returns_door_detail_with_status(self, mock_client):
        """get_door(id) returns DoorElement with DoorStatus parsed."""
        cli, _ = mock_client
        cli._call = lambda path, logical="GET", body_obj=None: DOOR_DETAIL_RESPONSE_DATA

        door = cli.get_door("996")
        assert door.id == "996"
        assert door.name == "Kalitka_SP1"
        assert door.magnet_state == 0
        assert door.lock_state == 1
        assert door.policy_state == 0
        assert door.overall_status == 0
        assert door.controller_id == "205"
        assert door.controller_address == "203.0.113.96"
        assert door.door_no == 1
        assert door.associated_cameras == ["11"]


class TestDiscoveryEndpoints:
    """Verify all discovery endpoints hit the right paths."""

    def test_get_camera_elements_path(self, mock_client):
        cli, mock_http = mock_client
        mock_http.post.return_value = FakeResponse(
            "<Response><Data><CameraElementList><CameraElement></CameraElement></CameraElementList></Data></Response>"
        )
        cli.get_camera_elements()
        url = mock_http.post.call_args.args[0]
        assert "CameraElements" in url

    def test_get_access_controllers_path(self, mock_client):
        cli, mock_http = mock_client
        mock_http.post.return_value = FakeResponse(
            "<Response><Data><AccessControllerList><AccessController></AccessController></AccessControllerList></Data></Response>"
        )
        cli.get_access_controllers()
        url = mock_http.post.call_args.args[0]
        assert "AccessControllers" in url

    def test_get_video_intercoms_path(self, mock_client):
        cli, mock_http = mock_client
        mock_http.post.return_value = FakeResponse(
            "<Response><Data><VideoIntercomList><VideoIntercom></VideoIntercom></VideoIntercomList></Data></Response>"
        )
        cli.get_video_intercoms()
        url = mock_http.post.call_args.args[0]
        assert "VideoIntercoms" in url

    def test_all_discovery_calls_include_append_info(self, mock_client):
        """Every discovery POST includes the AppendInfo header."""
        cli, mock_http = mock_client

        for xml_response in [
            "<Response><Data><AreaList><Area></Area></AreaList></Data></Response>",
            "<Response><Data><DoorElementList><DoorElement></DoorElement></DoorElementList></Data></Response>",
            "<Response><Data><CameraElementList><CameraElement></CameraElement></CameraElementList></Data></Response>",
            "<Response><Data><AccessControllerList><AccessController></AccessController></AccessControllerList></Data></Response>",
            "<Response><Data><VideoIntercomList><VideoIntercom></VideoIntercom></VideoIntercomList></Data></Response>",
        ]:
            mock_http.post.return_value = FakeResponse(xml_response)
            cli.get_areas()
            headers = mock_http.post.call_args.kwargs.get("headers", {})
            assert "AppendInfo" in headers, "AppendInfo header missing"
            assert len(headers["AppendInfo"]) > 0
