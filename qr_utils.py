
import json
import qrcode
from PIL import Image
from io import BytesIO
import base64

def paramdict_to_json(dct):
    return json.dumps(dct)

def paramdict_from_json(js):
    return json.loads(js)

def generate_qr_img(paramdict):
    js = paramdict_to_json(paramdict)
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(js)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    return img

def encode_qr_to_b64(paramdict):
    img = generate_qr_img(paramdict)
    buf = BytesIO()
    img.save(buf, format="PNG")
    b = buf.getvalue()
    return base64.b64encode(b).decode("utf-8")

def decode_qr_from_imagefile(filepath):
    from pyzbar.pyzbar import decode
    img = Image.open(filepath)
    decoded_objs = decode(img)
    if decoded_objs:
        js = decoded_objs[0].data.decode("utf-8")
        return paramdict_from_json(js)
    return None

def decode_qr_from_pil(img):
    from pyzbar.pyzbar import decode
    decoded_objs = decode(img)
    if decoded_objs:
        js = decoded_objs[0].data.decode("utf-8")
        return paramdict_from_json(js)
    return None

# Kontakt-QR
def contact_to_qr_img(name, pubkey_b64):
    dct = {"name": name, "pubkey": pubkey_b64}
    return generate_qr_img(dct)

def parse_contact_qr(img):
    from pyzbar.pyzbar import decode
    decoded_objs = decode(img)
    if decoded_objs:
        js = decoded_objs[0].data.decode("utf-8")
        dct = paramdict_from_json(js)
        return dct["name"], dct["pubkey"]
    return None, None
