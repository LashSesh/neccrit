from __future__ import annotations
import json, random, secrets, string, time
from typing import Any, Dict, Optional

def _rand_string(length: int = 8) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def fake_api_request_generator(seed: Optional[int] = None) -> Dict[str, Any]:
    if seed is not None:
        random.seed(seed)
    endpoints = ["/v1/users/login","/v1/items/search","/api/v2/metrics/submit"]
    methods = ["POST","GET","PUT"]
    endpoint = random.choice(endpoints)
    method = random.choice(methods)
    body = {"sample": _rand_string(6), "ts": _now_iso()}
    headers = {"Host": "api.example.com", "User-Agent": "neccrit/1.0"}
    return {"method": method, "endpoint": endpoint, "headers": headers, "body": body, "generated_at": _now_iso()}

def http_builder_transformer(payload: Any, host="api.example.com", include_length_prefix=True) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    header = f"POST {payload.get('endpoint','/')} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    req = header + body
    return len(req).to_bytes(4,"big") + req if include_length_prefix else req

_ZERO_WIDTH_ONE, _ZERO_WIDTH_ZERO = "\u200B", "\u200C"
def steganography_transformer(payload: Any) -> str:
    data = json.dumps(payload,separators=(",",":"),ensure_ascii=False).encode()
    bits = "".join(f"{b:08b}" for b in data)
    return "".join(_ZERO_WIDTH_ONE if bit=="1" else _ZERO_WIDTH_ZERO for bit in bits)

def steganography_decode(zws: str) -> str:
    bits = ["1" if c==_ZERO_WIDTH_ONE else "0" for c in zws if c in (_ZERO_WIDTH_ONE,_ZERO_WIDTH_ZERO)]
    bytes_out = [int("".join(bits[i:i+8]),2) for i in range(0,len(bits),8)]
    return bytes(bytes_out).decode("utf-8")

__all__ = ["fake_api_request_generator","http_builder_transformer","steganography_transformer","steganography_decode"]
