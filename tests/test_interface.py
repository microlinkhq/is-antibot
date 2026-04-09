"""Integration tests with real HTTP requests."""

import urllib.error
import urllib.request

import httpx
import pytest

from is_antibot import is_antibot

URL = "https://www.linkedin.com/in/kikobeats/"
HEADERS = {"User-Agent": "curl/7.81.0"}
VALID_DETECTIONS = {"headers", "cookies", "html", "url", "status_code"}


@pytest.mark.network
def test_from_httpx():
    response = httpx.get(URL, headers=HEADERS, follow_redirects=True)
    result = is_antibot(
        headers=dict(response.headers),
        status_code=response.status_code,
        html=response.text,
        url=str(response.url),
    )
    assert result.detected is True
    assert result.provider == "linkedin"
    assert result.detection in VALID_DETECTIONS


@pytest.mark.network
def test_from_urllib():
    req = urllib.request.Request(URL, headers=HEADERS)
    try:
        response = urllib.request.urlopen(req)
        html = response.read().decode()
        status_code = response.status
        headers = dict(response.headers)
        response_url = response.url
    except urllib.error.HTTPError as e:
        html = e.read().decode() if e.fp else ""
        status_code = e.code
        headers = dict(e.headers)
        response_url = URL

    result = is_antibot(
        headers=headers,
        status_code=status_code,
        html=html,
        url=response_url,
    )
    assert result.detected is True
    assert result.provider == "linkedin"
    assert result.detection in VALID_DETECTIONS
