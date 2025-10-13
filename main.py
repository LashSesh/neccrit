from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.image import Image as KivyImage
from kivy.core.image import Image as CoreImage
from kivy.uix.scrollview import ScrollView
from kivy.clock import Clock, mainthread
import threading, socket, pickle, time
from oscillator_core import OscillatorCore
from entropy_seed import generate_seed
from tripolar_mask import tripolar_mask, tripolar_unmask
from crypto_layer import derive_key, encrypt_bytes, decrypt_bytes
from qr_utils import encode_qr_to_b64, decode_qr_from_imagefile, generate_qr_img
import io, base64

try:
    from kivy.garden.xcamera import XCamera
    have_camera = True
except ImportError:
    have_camera = False

class ChatLogic:
    def __init__(self, update_callback):
        self.name = "User"
        self.port = 55555
        self.resonance_code = 1234
        self.kappa = [2.5, 3.1, 4.7]
        self.theta = [0.1, 1.3, 2.1]
        self.crypto_pw = "geheim"
        self.peer_ip = "127.0.0.1"
        self.peer_port = 55555
        self.osc = OscillatorCore([1,2,3,4,5,6,7,8,9,10,11])
        self.history = []
        self.running = False
        self.update_callback = update_callback
        self.crypto_key = derive_key(self.crypto_pw)

    def set_params(self, dct):
        self.name = dct["name"]
        self.port = int(dct["port"])
        self.resonance_code = int(dct["resonance_code"])
        self.kappa = [float(x) for x in dct["kappa"]]
        self.theta = [float(x) for x in dct["theta"]]
        self.crypto_pw = dct["crypto_pw"]
        self.crypto_key = derive_key(self.crypto_pw)
        self.peer_ip = dct["peer_ip"]
        self.peer_port = int(dct["peer_port"])

    def get_params(self):
        return {
            "name": self.name,
            "port": self.port,
            "resonance_code": self.resonance_code,
            "kappa": self.kappa,
            "theta": self.theta,
            "crypto_pw": self.crypto_pw,
            "peer_ip": self.peer_ip,
            "peer_port": self.peer_port
        }

    def start_listening(self):
        def server():
            self.running = True
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("", self.port))
                    s.listen(5)
                except Exception as e:
                    self.update_callback(f"[Fehler beim Start des Servers: {e}]")
                    return
                while self.running:
                    try:
                        conn, addr = s.accept()
                        with conn:
                            data = b""
                            while True:
                                chunk = conn.recv(4096)
                                if not chunk: break
                                data += chunk
                            try:
                                enc_payload = pickle.loads(data)
                                payload_raw = decrypt_bytes(enc_payload["payload"], self.crypto_key)
                                payload = pickle.loads(payload_raw)
                                masked = payload["fragment"]
                                seed = payload["seed"]
                                sender = payload["sender"]
                                t = payload["t"]
                                kappa = payload["kappa"]
                                theta = payload["theta"]
                                frag = tripolar_unmask(masked, kappa, theta, seed, t)
                                if self._resonant(frag):
                                    text = "".join([chr(int(round(x))) for x in frag if x>0 and x<1114111])
                                    self.history.append((sender, text))
                                    self.update_callback(f"[Von {sender}]: {text}")
                                else:
                                    self.update_callback(f"[Nicht resonant: Nachricht von {sender} ignoriert.]")
                            except Exception as e:
                                self.update_callback(f"[Fehler beim Entpacken: {e}]")
                    except Exception as e:
                        self.update_callback(f"[Socket-Fehler: {e}]")
        threading.Thread(target=server, daemon=True).start()

    def send_fragment(self, msg):
        signal = [ord(c) for c in msg]
        profile = self.osc.spectral_profile(signal)
        seed = generate_seed(length=2)
        seed_float = int.from_bytes(seed, "big") / 5000.0 + 1
        t = list(range(len(profile)))
        masked = tripolar_mask(profile, self.kappa, self.theta, seed_float, t)
        payload = {
            "fragment": masked,
            "seed": seed_float,
            "sender": self.name,
            "t": t,
            "kappa": self.kappa,
            "theta": self.theta
        }
        payload_bytes = pickle.dumps(payload)
        enc_payload = {"payload": encrypt_bytes(payload_bytes, self.crypto_key)}
        data = pickle.dumps(enc_payload)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.peer_ip, self.peer_port))
                s.sendall(data)
            self.history.append((self.name, msg))
            self.update_callback(f"[Du]: {msg}")
        except Exception as e:
            self.update_callback(f"[Fehler beim Senden: {e}]")

    def _resonant(self, fragment):
        s = sum(fragment)
        try:
            return int(s) % int(self.resonance_code) == 0
        except Exception:
            return False

class PrivacyChatUI(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", **kwargs)
        self.logic = ChatLogic(self.add_message)
        self.build_ui()

    def build_ui(self):
        # Einstellungen-Panel
        self.param_box = BoxLayout(size_hint_y=0.25, orientation="vertical")
        self.name_in = TextInput(hint_text="Name", multiline=False, text="User")
        self.port_in = TextInput(hint_text="Eigener Port", multiline=False, text="55555")
        self.res_in = TextInput(hint_text="Resonanzcode", multiline=False, text="1234")
        self.kappa_in = TextInput(hint_text="kappa (z.B. 2.5,3.1,4.7)", multiline=False, text="2.5,3.1,4.7")
        self.theta_in = TextInput(hint_text="theta (z.B. 0.1,1.3,2.1)", multiline=False, text="0.1,1.3,2.1")
        self.crypto_pw_in = TextInput(hint_text="AES/Fernet Passwort", multiline=False, text="geheim")
        self.peer_ip_in = TextInput(hint_text="Peer-IP", multiline=False, text="127.0.0.1")
        self.peer_port_in = TextInput(hint_text="Peer-Port", multiline=False, text="55555")
        self.start_btn = Button(text="Starten", size_hint_y=0.7, on_press=self.start_chat)
        # QR-Buttons
        self.qr_show_btn = Button(text="QR anzeigen", size_hint_y=0.5, on_press=self.show_my_qr)
        self.qr_scan_btn = Button(text="QR scannen", size_hint_y=0.5, on_press=self.scan_qr)
        self.param_box.add_widget(self.name_in)
        self.param_box.add_widget(self.port_in)
        self.param_box.add_widget(self.res_in)
        self.param_box.add_widget(self.kappa_in)
        self.param_box.add_widget(self.theta_in)
        self.param_box.add_widget(self.crypto_pw_in)
        self.param_box.add_widget(self.peer_ip_in)
        self.param_box.add_widget(self.peer_port_in)
        self.param_box.add_widget(self.start_btn)
        self.param_box.add_widget(self.qr_show_btn)
        self.param_box.add_widget(self.qr_scan_btn)
        self.add_widget(self.param_box)

        # Verlauf
        self.scroll = ScrollView(size_hint_y=0.55)
        self.msg_label = Label(size_hint_y=None, height=1000, text="[Verlauf]", valign="top", halign="left", markup=True)
        self.msg_label.bind(size=self._update_text_size)
        self.scroll.add_widget(self.msg_label)
        self.add_widget(self.scroll)

        # Eingabefeld
        self.input_box = BoxLayout(size_hint_y=0.2)
        self.msg_in = TextInput(hint_text="Nachricht...", multiline=False)
        self.send_btn = Button(text="Senden", on_press=self.send_message)
        self.input_box.add_widget(self.msg_in)
        self.input_box.add_widget(self.send_btn)
        self.add_widget(self.input_box)

        self.send_btn.disabled = True
        self.msg_in.disabled = True

    def _update_text_size(self, instance, value):
        self.msg_label.text_size = (self.msg_label.width, None)

    @mainthread
    def add_message(self, msg):
        self.msg_label.text += f"\n{msg}"
        self.scroll.scroll_y = 0

    def start_chat(self, instance):
        try:
            self.logic.name = self.name_in.text.strip() or "User"
            self.logic.port = int(self.port_in.text.strip())
            self.logic.resonance_code = int(self.res_in.text.strip())
            self.logic.kappa = [float(x) for x in self.kappa_in.text.strip().split(",")]
            self.logic.theta = [float(x) for x in self.theta_in.text.strip().split(",")]
            self.logic.crypto_pw = self.crypto_pw_in.text.strip()
            self.logic.crypto_key = derive_key(self.logic.crypto_pw)
            self.logic.peer_ip = self.peer_ip_in.text.strip()
            self.logic.peer_port = int(self.peer_port_in.text.strip())
            self.logic.start_listening()
            self.add_message("[Chat gestartet]")
            self.send_btn.disabled = False
            self.msg_in.disabled = False
            self.start_btn.disabled = True
            for field in [self.name_in, self.port_in, self.res_in, self.kappa_in, self.theta_in, self.crypto_pw_in, self.peer_ip_in, self.peer_port_in]:
                field.disabled = True
        except Exception as e:
            Popup(title="Fehler", content=Label(text=str(e)), size_hint=(.7,.2)).open()

    def send_message(self, instance):
        msg = self.msg_in.text.strip()
        if msg:
            threading.Thread(target=self.logic.send_fragment, args=(msg,), daemon=True).start()
            self.msg_in.text = ""

    def show_my_qr(self, instance):
        # Zeigt eigenen QR-Code als Popup
        params = self.logic.get_params()
        img = generate_qr_img(params)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        ci = CoreImage(buf, ext="png")
        img_widget = KivyImage(texture=ci.texture, size_hint=(1,1))
        popup = Popup(title="Mein QR", content=img_widget, size_hint=(.6,.6))
        popup.open()

    def scan_qr(self, instance):
        # QR von Kamera lesen, Felder automatisch setzen
        if not have_camera:
            Popup(title="Kamera fehlt!", content=Label(text="Bitte installiere kivy-garden.xcamera!"), size_hint=(.7,.2)).open()
            return
        cam_popup = Popup(title="QR scannen (Kamera)", size_hint=(0.8, 0.8))
        cam_widget = XCamera(play=True)
        cam_popup.content = cam_widget
        def on_picture_taken(widget, filepath):
            try:
                dct = decode_qr_from_imagefile(filepath)
                if dct:
                    self.logic.set_params(dct)
                    self.name_in.text = dct["name"]
                    self.port_in.text = str(dct["port"])
                    self.res_in.text = str(dct["resonance_code"])
                    self.kappa_in.text = ",".join(str(x) for x in dct["kappa"])
                    self.theta_in.text = ",".join(str(x) for x in dct["theta"])
                    self.crypto_pw_in.text = dct["crypto_pw"]
                    self.peer_ip_in.text = dct["peer_ip"]
                    self.peer_port_in.text = str(dct["peer_port"])
                    self.add_message("[QR übernommen!]")
                else:
                    self.add_message("[Kein gültiger QR-Code!]")
            except Exception as e:
                self.add_message(f"[Fehler beim QR-Scan: {e}]")
            cam_popup.dismiss()
        cam_widget.bind(on_picture_taken=on_picture_taken)
        cam_popup.open()

class PrivacyChatApp(App):
    def build(self):
        return PrivacyChatUI()

if __name__ == "__main__":
    PrivacyChatApp().run()
