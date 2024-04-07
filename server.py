from __future__ import annotations
import argparse
import socket
import threading
from contextlib import suppress
from typing import Any, Callable, NoReturn, Optional, Tuple, Union
from threading import Lock, Event

from mbedtls._tls import _enable_debug_output, _set_debug_level
from mbedtls.pk import ECC, RSA
from mbedtls.tls import (
    DTLSConfiguration,
    HelloVerifyRequest,
    ServerContext,
    TLSWrappedSocket,
)
from mbedtls.x509 import CRT

_Address: TypeAlias = Union[Tuple[Any, ...], str]

def _make_dtls_connection(sock: TLSWrappedSocket) -> Tuple[TLSWrappedSocket, Tuple[str, int]]:
    assert sock
    conn, addr = sock.accept()
    conn.setcookieparam(addr[0].encode("ascii"))
    with suppress(HelloVerifyRequest):
        conn.do_handshake()

    _, (conn, addr) = conn, conn.accept()
    _.close()
    conn.setcookieparam(addr[0].encode("ascii"))
    conn.do_handshake()
    return conn, addr

class Server:
    def __init__(
        self,
        srv_conf: Union[DTLSConfiguration],
        proto: socket.SocketKind,
        address: _Address,
    ) -> None:
        self.srv_conf = srv_conf
        self.proto = proto
        self.address = address
        self._make_connection = _make_dtls_connection
        self._sock: Optional[TLSWrappedSocket] = None
        self.active_connections: dict[str, Tuple[TLSWrappedSocket, threading.Thread, Event]] = {}
        self.active_connections_lock = Lock()

    def __enter__(self) -> Server:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def __del__(self) -> None:
        self.stop()

    def start(self) -> None:
        if self._sock:
            self.stop()

        self._sock = ServerContext(self.srv_conf).wrap_socket(
            socket.socket(socket.AF_INET, self.proto)
        )
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self.address)

    def stop(self) -> None:
        if not self._sock:
            return
        self._sock.close()
        self._sock = None

    def run(self, conn_handler: Callable[[TLSWrappedSocket, Tuple[str, int], Event], None]) -> NoReturn:
        if not self._sock:
            raise ConnectionRefusedError("server not started")

        while True:
            conn, addr = self._make_connection(self._sock)
            ip = addr[0]
            with self.active_connections_lock:
                if ip in self.active_connections:
                    print(ip,"in open connections")
                    _, old_thread, stop_signal = self.active_connections[ip]
                    stop_signal.set()  # Signal the old thread to stop

                    old_thread.join(timeout=1)  # Wait a bit for the thread to terminate
                    if old_thread.is_alive():
                        print("Old thread did not terminate in time, it might still be running!")

                stop_signal = Event()
                thread = threading.Thread(target=conn_handler, args=(conn, addr, stop_signal))
                self.active_connections[ip] = (conn, thread, stop_signal)
                thread.start()

    def handle_disconnect(self, ip):
        with self.active_connections_lock:
            if ip in self.active_connections:
                _, _, stop_signal = self.active_connections[ip]
                stop_signal.set()
                del self.active_connections[ip]

def echo_handler(conn: TLSWrappedSocket, addr, stop_signal: Event):
    ip = addr[0]
    print(f"Connection from {ip}")
    try:
        conn.settimeout(1.0)  # Allow periodic checking of the stop_signal
        while not stop_signal.is_set():
            try:
                data = conn.recv(1024)
                if not data:
                    break
                conn.send(data)
            except socket.timeout:
                continue
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="DTLS server example")
    parser.add_argument("--address", default="0.0.0.0")
    parser.add_argument("--port", default=4433, type=int)
    cert = CRT.from_file("cert.pem")
    key = RSA.from_file("key.pem")
    conf = DTLSConfiguration(
        certificate_chain=((cert,), key),
        validate_certificates=False,
    )

    with Server(conf, socket.SOCK_DGRAM, (parser.parse_args().address, parser.parse_args().port)) as srv:
        srv.run(echo_handler)

if __name__ == "__main__":
    main()
