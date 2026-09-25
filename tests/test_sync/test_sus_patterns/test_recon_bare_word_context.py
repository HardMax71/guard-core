import json

import pytest

from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

# Ordinary field values that the whole-value recon rows match when the leading "/"
# is optional: product names, enum values, file names.
_BARE_WORDS = [
    "default",
    "SAP",
    "ise",
    "language",
    "autodiscover",
    "confluence",
    "actuator",
    "cgi-bin",
    "lms/db",
    "README.md",
    "CHANGELOG",
    "Makefile",
    "credentials.json",
    "report.asp",
]
_PROBE_PATHS = [
    "/default.asp",
    "/sap",
    "\\default",
    "/actuator/health",
    "/cgi-bin/test.cgi",
    "/README.md",
]
_JSON = {"content-type": "application/json"}
_FORM = {"content-type": "application/x-www-form-urlencoded"}


def _requests(value: str) -> list[SyncMockGuardRequest]:
    return [
        SyncMockGuardRequest(path="/items", query_params={"system": value}),
        SyncMockGuardRequest(
            path="/items",
            method="POST",
            headers=_JSON,
            body_content=json.dumps({"system": value}).encode(),
        ),
        SyncMockGuardRequest(
            path="/items",
            method="POST",
            headers=_FORM,
            body_content=f"system={value}".encode(),
        ),
        SyncMockGuardRequest(
            path="/items", query_params={"v": json.dumps({"system": value})}
        ),
    ]


def _threat_categories(request: SyncMockGuardRequest) -> list[str]:
    result = detect_penetration_attempt(request)
    return list(result.threat_categories) if result.is_threat else []


@pytest.mark.parametrize("value", _BARE_WORDS)
def test_bare_word_query_or_body_value_is_not_a_recon_probe(value: str) -> None:
    for request in _requests(value):
        assert _threat_categories(request) == []


@pytest.mark.parametrize("value", _PROBE_PATHS)
def test_probe_path_as_a_query_or_body_value_is_still_recon(value: str) -> None:
    for request in _requests(value):
        assert "recon" in _threat_categories(request)


@pytest.mark.parametrize("value", ["default", "sap", "README.md", "actuator"])
def test_bare_word_as_the_url_path_is_still_recon(value: str) -> None:
    assert "recon" in _threat_categories(SyncMockGuardRequest(path=f"/{value}"))
