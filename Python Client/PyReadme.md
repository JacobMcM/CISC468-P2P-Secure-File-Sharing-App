# python Client

## Windows

### Python version
use 3.14.3

### Install dependencies

```powershell
pip install -r requirements.txt
```

Update Peer passwords in storage.py
(this would have been automated, and encrypted if Python client had reached completion)

### run

```powershell
pip install -r requirements.txt
```

## Usage

On startup the client will Display all peers connected to the network. Entering "r" will refresh this list, "x" will exit from the service. 

By typeing the username of one of the peers on the network, the system will attempt to establish a connection.

If a connection is established, the user will have 5 options
(1) Request File List
(2) Request File
(3) Send File
(x) Close Connection
(r or any other input) Refresh Options

Note: options 1-3 are not implemented, see limitations

### Limitations
All peers must be on the **same local network** for mDNS discovery to work.

Python client does not have file storage for file transport implementation.
This means that it can establish connections with other peers, but it cannot send files, requests for files, or filelist. It also will not respond to any messages sent after connection is established
