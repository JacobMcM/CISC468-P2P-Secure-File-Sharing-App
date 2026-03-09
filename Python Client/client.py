from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf, ZeroconfServiceTypes
import socket
import os
from dotenv import load_dotenv

load_dotenv()
JACOBIP = os.getenv('JACOBIP')

zeroconf = Zeroconf()

info = ServiceInfo(
    "_p2p._tcp.local.",
    "JacobPC._p2p._tcp.local.",
    addresses=[socket.inet_aton(JACOBIP)], # < My local
    port=5000,
)
zeroconf.register_service(info)

services = {}  # will hold name -> ServiceInfo


class MyListener(ServiceListener):
    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"Service {name} updated")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"Service {name} removed")
        services.pop(name,None)

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            services[name] = info
            print(f"Service {name} added, ip: {socket.inet_ntop(socket.AF_INET, info.addresses[0])}, port: {info.port}")

listener = MyListener()
browser = ServiceBrowser(zeroconf, "_p2p._tcp.local.", listener)
try:
    input("Press enter to exit...\n\n")
finally:
    zeroconf.unregister_service(info)
    zeroconf.close()