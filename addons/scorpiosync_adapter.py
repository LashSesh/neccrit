import random, threading, time
from .scorpiosync_generators_complete import fake_api_request_generator, http_builder_transformer, steganography_transformer
from core.transport import send_encrypted_json, is_session_ready

def maybe_transform_plaintext(plaintext: str, use_stegano: bool) -> str:
    return steganography_transformer(plaintext) if use_stegano else plaintext

def send_cover_once(use_http_mimicry: bool):
    payload = fake_api_request_generator()
    frame = {"type": "cover", "payload": payload, "ts": int(time.time())}
    if use_http_mimicry:
        _ = http_builder_transformer(payload, include_length_prefix=False)
    send_encrypted_json(frame)

def start_cover_traffic(min_s: int, max_s: int, use_http_mimicry: bool, stop_flag):
    def _loop():
        while not stop_flag.is_set():
            if is_session_ready():
                try: send_cover_once(use_http_mimicry)
                except Exception: pass
            time.sleep(random.randint(min_s, max_s))
    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t
