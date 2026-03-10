import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from onedrive_proxy import derive_sharepoint_host

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
