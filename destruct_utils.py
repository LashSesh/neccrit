
import threading
import os
import time

destruct_flags = {}

def set_self_destruct(msg_id, seconds, callback):
    def destruct():
        time.sleep(seconds)
        if destruct_flags.get(msg_id, True):
            callback(msg_id)
    t = threading.Thread(target=destruct)
    t.start()

def cancel_self_destruct(msg_id):
    destruct_flags[msg_id] = False
