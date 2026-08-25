import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.ioc_detector import detect_ioc_type


def test_ipv4():
    result = detect_ioc_type("8.8.8.8")
    assert result["valid"] is True
    assert result["type"] == "ipv4"


def test_ipv6():
    result = detect_ioc_type("2001:4860:4860::8888")
    assert result["valid"] is True
    assert result["type"] == "ipv6"


def test_domain():
    result = detect_ioc_type("example.com")
    assert result["valid"] is True
    assert result["type"] == "domain"


def test_url():
    result = detect_ioc_type("https://example.com/path?query=1")
    assert result["valid"] is True
    assert result["type"] == "url"


def test_md5():
    result = detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e")
    assert result["valid"] is True
    assert result["type"] == "md5"


def test_sha1():
    result = detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert result["valid"] is True
    assert result["type"] == "sha1"


def test_sha256():
    result = detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85")
    assert result["valid"] is True
    assert result["type"] == "sha256"


def test_invalid_input():
    result = detect_ioc_type("not a valid indicator!!!")
    assert result["valid"] is False


def test_empty_input():
    result = detect_ioc_type("   ")
    assert result["valid"] is False