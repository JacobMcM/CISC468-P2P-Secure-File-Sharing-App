# storage.py
import json, os

DATA_PATH = "network.json"

public_keys = {}
fileList = {}

def load():
    global public_keys, fileList
    if not os.path.exists(DATA_PATH):
        return
    with open(DATA_PATH) as f:
        data = json.load(f)
        public_keys = data.get("public_keys", {})
        fileList = data.get("fileList", {})

def save():
    global public_keys, fileList
    with open(DATA_PATH, "w") as f:
        data = {
            "public_keys" : public_keys,
            "fileList" : fileList
        }
        json.dump(data, f, indent=4)

