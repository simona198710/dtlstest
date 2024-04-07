import socket
from mbedtls.tls import DTLSConfiguration, ClientContext
from mbedtls.x509 import CRT
from mbedtls.pk import RSA
import time

# Load the certificate and key
cert_file_path = "cert.pem"
key_file_path = "key.pem"
with open(cert_file_path, "r") as cert_file, open(key_file_path, "r") as key_file:
    cert = CRT.from_PEM(cert_file.read())
    key = RSA.from_PEM(key_file.read())

# Create a DTLS configuration object
conf = DTLSConfiguration(
    certificate_chain=((cert,), key),
    validate_certificates=False,
)

class DTLSClient:
    def __init__(self, configuration, server_address, server_hostname):
        self.configuration = configuration
        self.server_address = server_address
        self.server_hostname = server_hostname
        self.sock = None

    def start(self):
        self.sock = ClientContext(self.configuration).wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
            server_hostname=self.server_hostname,
        )
        self.sock.connect(self.server_address)
        self.complete_handshake()

    def complete_handshake(self):
        try:
            self.sock.do_handshake()
        except Exception as e:
            print(f"Handshake failed: {e}")

    def stop(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_and_receive(self, message):
        if not self.sock:
            print("Client not started.")
            return ""
        self.sock.send(message.encode())
        return self.sock.recv(1024).decode()
        #return ""

# Usage example
server_hostname = "localhost"
server_address = (server_hostname, 4433)
client = DTLSClient(conf, server_address, server_hostname)
try:
    client.start()
    start_time = time.time()
    response = client.send_and_receive("Hello, DTLS Server!")
    print(f"Received: {response}")
    #client.stop()
    #client.start()
    response = client.send_and_receive("Hello, DTLS Server2!")
    print(f"Received: {response}")
    time.sleep(10)
    response = client.send_and_receive("Hello, DTLS Server3!")
    init_time = time.time()
    print(f"Client init took {init_time - start_time:.4f} seconds")
    print(f"Received: {response}")
finally:
    client.stop()

message_time = time.time()
print(f"Message took {message_time - init_time:.4f} seconds")
