
import os
import time
import ctypes
import platform

def is_virtualized():
    try:
        with open("/proc/cpuinfo", "r") as f:
            cpuinfo = f.read().lower()
        if "hypervisor" in cpuinfo or "vmware" in cpuinfo or "vbox" in cpuinfo:
            return True
    except:
        pass
    return False

def is_remote_session():
    if platform.system() == "Windows":
        return "SESSIONNAME" in os.environ and "RDP" in os.environ["SESSIONNAME"]
    return False

def no_user_activity(timeout=15):
    if platform.system() == "Windows":
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            elapsed = (ctypes.windll.kernel32.GetTickCount() - lii.dwTime) / 1000
            return elapsed > timeout
    return False

def should_blackscreen():
    return is_virtualized() or is_remote_session() or no_user_activity()
