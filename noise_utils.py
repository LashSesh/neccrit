
import os
import time
import random

def add_noise_to_message(msg: bytes, min_noise=16, max_noise=64):
    noise_len = random.randint(min_noise, max_noise)
    noise = os.urandom(noise_len)
    return noise + msg

def strip_noise_from_message(msg: bytes, original_len: int):
    return msg[-original_len:]

def simulate_network_noise():
    time.sleep(random.uniform(0.05, 0.4))  # Delay injection to randomize timing
