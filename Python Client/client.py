from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf, ZeroconfServiceTypes
import socket

zeroconf = Zeroconf()

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)
print(ip)
info = ServiceInfo(
    "_p2p._tcp.local.",
    "JacobPC._p2p._tcp.local.",
    addresses=[socket.inet_aton(ip)],
    port=5000,
)
zeroconf.register_service(info)


class MyListener(ServiceListener):
    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"Service {name} updated")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"Service {name} removed")

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        print(f"Service {name} added, service info: {info}")

listener = MyListener()
browser = ServiceBrowser(zeroconf, "_p2p._tcp.local.", listener)
try:
    input("Press enter to exit...\n\n")
finally:
    zeroconf.unregister_service(info)
    zeroconf.close()