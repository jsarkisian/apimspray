import pytest
import sys
import os
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from onedrive_proxy import derive_sharepoint_host, verify_tenant

def test_domain_tenant():
    assert derive_sharepoint_host("contoso.com") == "contoso-my.sharepoint.com"

def test_onmicrosoft_tenant():
    assert derive_sharepoint_host("contoso.onmicrosoft.com") == "contoso-my.sharepoint.com"

def test_bare_tenant():
    assert derive_sharepoint_host("contoso") == "contoso-my.sharepoint.com"

def test_uuid_tenant_with_domain():
    assert derive_sharepoint_host(
        "12345678-1234-1234-1234-123456789abc", domain="contoso.com"
    ) == "contoso-my.sharepoint.com"

def test_uuid_tenant_without_domain():
    with pytest.raises(ValueError):
        derive_sharepoint_host("12345678-1234-1234-1234-123456789abc")


# --- verify_tenant ---

def test_verify_tenant_valid_on_403():
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    with patch("onedrive_proxy.requests.get", return_value=mock_resp):
        ok, status = verify_tenant("contoso-my.sharepoint.com")
    assert ok is True
    assert status == 403

def test_verify_tenant_valid_on_302():
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    with patch("onedrive_proxy.requests.get", return_value=mock_resp):
        ok, status = verify_tenant("contoso-my.sharepoint.com")
    assert ok is True

def test_verify_tenant_invalid_on_404():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch("onedrive_proxy.requests.get", return_value=mock_resp):
        ok, status = verify_tenant("nonexistent-my.sharepoint.com")
    assert ok is False
    assert status == 404

def test_verify_tenant_invalid_on_exception():
    import requests as req
    with patch("onedrive_proxy.requests.get", side_effect=req.RequestException("timeout")):
        ok, status = verify_tenant("nonexistent-my.sharepoint.com")
    assert ok is False
    assert status is None
