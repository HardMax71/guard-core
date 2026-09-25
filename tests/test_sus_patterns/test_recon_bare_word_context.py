import json
from collections.abc import Iterator

import pytest

from guard_core.handlers.suspatterns_handler import (
    _LEGACY_DETECTION_STATE,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest


@pytest.fixture(autouse=True)
def _pin_legacy_detection_singleton() -> Iterator[None]:
    # Earlier files in this directory reconfigure the singleton through their
    # own finalizers, which run after the conftest's teardown restore; these
    # tests assume the legacy unconfigured handler, so pin it before each test.
    sus_patterns_handler._compiler = None
    sus_patterns_handler._preprocessor = None
    sus_patterns_handler._semantic_analyzer = None
    sus_patterns_handler._performance_monitor = None
    sus_patterns_handler._threat_score_threshold = 1.0
    sus_patterns_handler._detection_state = _LEGACY_DETECTION_STATE
    SusPatternsManager._config = None
    yield


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


def _requests(value: str) -> list[MockGuardRequest]:
    return [
        MockGuardRequest(path="/items", query_params={"system": value}),
        MockGuardRequest(
            path="/items",
            method="POST",
            headers=_JSON,
            body_content=json.dumps({"system": value}).encode(),
        ),
        MockGuardRequest(
            path="/items",
            method="POST",
            headers=_FORM,
            body_content=f"system={value}".encode(),
        ),
        MockGuardRequest(
            path="/items", query_params={"v": json.dumps({"system": value})}
        ),
    ]


async def _threat_categories(request: MockGuardRequest) -> list[str]:
    result = await detect_penetration_attempt(request)
    return list(result.threat_categories) if result.is_threat else []


@pytest.mark.parametrize("value", _BARE_WORDS)
async def test_bare_word_query_or_body_value_is_not_a_recon_probe(value: str) -> None:
    for request in _requests(value):
        assert await _threat_categories(request) == []


@pytest.mark.parametrize("value", _PROBE_PATHS)
async def test_probe_path_as_a_query_or_body_value_is_still_recon(value: str) -> None:
    for request in _requests(value):
        assert "recon" in await _threat_categories(request)


@pytest.mark.parametrize("value", ["default", "sap", "README.md", "actuator"])
async def test_bare_word_as_the_url_path_is_still_recon(value: str) -> None:
    assert "recon" in await _threat_categories(MockGuardRequest(path=f"/{value}"))
