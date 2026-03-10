import pytest
import sys
import os
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from onedrive_enum import OneDriveEnumerator, build_onedrive_path


# --- URL construction ---

def test_simple_upn():
    path = build_onedrive_path("john.doe@contoso.com")
    assert path == "personal/john_doe_contoso_com/_layouts/15/onedrive.aspx"

def test_hyphen_in_username():
    path = build_onedrive_path("john-doe@contoso.com")
    assert path == "personal/john_doe_contoso_com/_layouts/15/onedrive.aspx"

def test_dots_in_domain():
    path = build_onedrive_path("alice@sub.contoso.com")
    assert path == "personal/alice_sub_contoso_com/_layouts/15/onedrive.aspx"

def test_uppercase_normalised():
    path = build_onedrive_path("John.Doe@Contoso.COM")
    assert path == "personal/john_doe_contoso_com/_layouts/15/onedrive.aspx"


# --- HTTP check ---

def _make_enumerator():
    return OneDriveEnumerator(proxy_urls=[])


def test_check_user_valid(tmp_path):
    """403 response means valid user."""
    enum = _make_enumerator()
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    with patch("onedrive_enum.requests.get", return_value=mock_resp):
        result = enum._check_user("john.doe@contoso.com", "contoso")
    assert result == "valid"


def test_check_user_not_found(tmp_path):
    """404 response means user not found."""
    enum = _make_enumerator()
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch("onedrive_enum.requests.get", return_value=mock_resp):
        result = enum._check_user("nobody@contoso.com", "contoso")
    assert result == "not_found"


def test_check_user_error_on_exception():
    """Network exception returns 'error'."""
    import requests as req
    enum = _make_enumerator()
    with patch("onedrive_enum.requests.get", side_effect=req.RequestException("timeout")):
        result = enum._check_user("john.doe@contoso.com", "contoso")
    assert result == "error"


def test_check_user_via_proxy():
    """When proxy_url provided, request goes to proxy URL not direct."""
    enum = _make_enumerator()
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    captured = {}
    def fake_get(url, **kwargs):
        captured["url"] = url
        return mock_resp
    with patch("onedrive_enum.requests.get", side_effect=fake_get):
        enum._check_user("john@contoso.com", "contoso", proxy_url="http://1.2.3.4:8080/")
    assert captured["url"].startswith("http://1.2.3.4:8080/")
    assert "personal/" in captured["url"]
