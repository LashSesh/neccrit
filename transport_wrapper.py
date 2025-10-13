
import base64
import json
import random

def wrap_payload(payload: bytes, mode='json') -> bytes:
    if mode == 'json':
        data = {
            "msg": base64.b64encode(payload).decode("utf-8"),
            "nonce": random.randint(100000, 999999),
            "meta": "chat-transport"
        }
        return json.dumps(data).encode("utf-8")
    elif mode == 'http':
        # Wrap as dummy HTTP POST
        b64 = base64.b64encode(payload).decode("utf-8")
        http_msg = f"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: {len(b64)}\r\n\r\n{b64}"
        return http_msg.encode("utf-8")
    else:
        raise ValueError("Unsupported transport mode")

def unwrap_payload(raw: bytes, mode='json') -> bytes:
    if mode == 'json':
        try:
            data = json.loads(raw.decode("utf-8"))
            return base64.b64decode(data["msg"].encode("utf-8"))
        except Exception:
            return b""
    elif mode == 'http':
        try:
            parts = raw.decode("utf-8").split("\r\n\r\n")
            b64 = parts[-1]
            return base64.b64decode(b64.encode("utf-8"))
        except Exception:
            return b""
    else:
        raise ValueError("Unsupported transport mode")
