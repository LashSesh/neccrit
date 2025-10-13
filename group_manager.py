
import json
import os

GROUPS_FILE = os.path.expanduser("~/.spectralship_groups.json")

def load_groups():
    if not os.path.exists(GROUPS_FILE):
        return {}
    with open(GROUPS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_groups(groups):
    with open(GROUPS_FILE, "w", encoding="utf-8") as f:
        json.dump(groups, f, indent=2)

def create_group(name, members):
    groups = load_groups()
    if name in groups:
        raise ValueError("Group already exists")
    groups[name] = {"members": members}
    save_groups(groups)

def list_groups():
    return list(load_groups().keys())

def get_group_members(name):
    groups = load_groups()
    return groups.get(name, {}).get("members", [])

def add_member_to_group(name, new_member_pubkey):
    groups = load_groups()
    if name not in groups:
        raise ValueError("Group does not exist")
    groups[name]["members"].append(new_member_pubkey)
    save_groups(groups)

def export_group_qrdata(name):
    groups = load_groups()
    if name not in groups:
        raise ValueError("Group not found")
    return groups[name]

def import_group_from_data(name, data):
    groups = load_groups()
    groups[name] = data
    save_groups(groups)
