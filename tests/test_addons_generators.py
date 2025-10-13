"""
Tests for scorpiosync_generators_complete module.

Tests cover traffic generation, HTTP formatting, and steganography functions.
"""
import json
import pytest

from addons.scorpiosync_generators_complete import (
    fake_api_request_generator,
    http_builder_transformer,
    steganography_transformer,
    steganography_decode,
)


def test_fake_api_request_generator_structure():
    """Test that fake API requests have expected structure."""
    payload = fake_api_request_generator()
    
    assert "method" in payload
    assert "endpoint" in payload
    assert "headers" in payload
    assert "body" in payload
    assert "generated_at" in payload
    
    assert payload["method"] in ["POST", "GET", "PUT"]
    assert payload["endpoint"] in ["/v1/users/login", "/v1/items/search", "/api/v2/metrics/submit"]
    assert "Host" in payload["headers"]
    assert "User-Agent" in payload["headers"]


def test_fake_api_request_generator_deterministic_with_seed():
    """Test that same seed produces same output."""
    payload1 = fake_api_request_generator(seed=42)
    payload2 = fake_api_request_generator(seed=42)
    
    # Same seed should produce same method and endpoint
    assert payload1["method"] == payload2["method"]
    assert payload1["endpoint"] == payload2["endpoint"]


def test_fake_api_request_generator_randomness_without_seed():
    """Test that without seed, outputs vary (probabilistic test)."""
    payloads = [fake_api_request_generator() for _ in range(10)]
    
    # At least some variation in endpoints or methods (very high probability)
    methods = {p["method"] for p in payloads}
    endpoints = {p["endpoint"] for p in payloads}
    
    # With 10 samples, we should see some variety (not 100% guaranteed but very likely)
    assert len(methods) > 1 or len(endpoints) > 1


def test_http_builder_transformer_with_prefix():
    """Test HTTP request building with length prefix."""
    payload = {"endpoint": "/test", "data": "value"}
    result = http_builder_transformer(payload, host="test.com", include_length_prefix=True)
    
    # Should have 4-byte length prefix
    assert len(result) > 4
    length = int.from_bytes(result[:4], "big")
    assert length == len(result) - 4
    
    # Rest should be valid HTTP
    http_part = result[4:].decode()
    assert "POST /test HTTP/1.1" in http_part
    assert "Host: test.com" in http_part
    assert "Content-Type: application/json" in http_part


def test_http_builder_transformer_without_prefix():
    """Test HTTP request building without length prefix."""
    payload = {"endpoint": "/api/v1/test", "key": "value"}
    result = http_builder_transformer(payload, include_length_prefix=False)
    
    http_str = result.decode()
    assert "POST /api/v1/test HTTP/1.1" in http_str
    assert "Content-Type: application/json" in http_str
    assert "Content-Length:" in http_str
    assert '"key":"value"' in http_str or '"key": "value"' in http_str


def test_steganography_roundtrip():
    """Test steganography encoding and decoding roundtrip."""
    original = {"message": "secret", "code": 123}
    
    # Encode
    encoded = steganography_transformer(original)
    
    # Should contain zero-width characters
    assert "\u200B" in encoded or "\u200C" in encoded
    assert len(encoded) > 0
    
    # Decode
    decoded_str = steganography_decode(encoded)
    decoded = json.loads(decoded_str)
    
    # Should match original
    assert decoded == original


def test_steganography_transformer_output_invisible():
    """Test that steganography output uses only zero-width chars."""
    payload = {"test": "data"}
    encoded = steganography_transformer(payload)
    
    # All characters should be zero-width
    allowed_chars = {"\u200B", "\u200C"}
    for char in encoded:
        assert char in allowed_chars


def test_steganography_decode_handles_mixed_content():
    """Test that decode extracts zero-width chars from mixed content."""
    # Create a simple encoded message
    original = {"x": 1}
    encoded = steganography_transformer(original)
    
    # Mix with visible characters
    mixed = f"visible text {encoded} more visible"
    
    # Should still decode correctly
    decoded_str = steganography_decode(mixed)
    decoded = json.loads(decoded_str)
    assert decoded == original


def test_http_builder_uses_correct_endpoint():
    """Test that HTTP builder respects the endpoint in payload."""
    payload = {"endpoint": "/custom/path", "data": "test"}
    result = http_builder_transformer(payload, include_length_prefix=False)
    
    http_str = result.decode()
    assert "POST /custom/path HTTP/1.1" in http_str


def test_http_builder_falls_back_to_root():
    """Test that HTTP builder uses root path when no endpoint provided."""
    payload = {"data": "test"}
    result = http_builder_transformer(payload, include_length_prefix=False)
    
    http_str = result.decode()
    assert "POST / HTTP/1.1" in http_str
