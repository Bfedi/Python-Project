from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import pika
import os
import json

class CaClient:
    def __init__(self, username):
        self.username = username
        self.client_key_path = "client_key.pem"
        self.client_csr_path = "client_csr.pem"
        self.cert_req_queue = "cert_req_queue"
        self.cert_exchange = "cert_exchange"
        self.cert_queue_name = f"{self.username}_cert_queue"

    def handle_cert_local(self, cert_path):
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as cert_file:
                cert_data = cert_file.read()
                try:
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    print(f"Issuer: {cert.issuer}")
                    print(f"Version: {cert.version}")
                    print(f"Subject: {cert.subject}")
                    return cert
                except Exception as e:
                    print(f"Error loading certificate: {e}")
        else:
            print(f"Certificate file not found: {cert_path}")
        return None

    def handle_cert(self, cert_data):
        try:
            cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
            print(f"Issuer: {cert.issuer}")
            print(f"Version: {cert.version}")
            print(f"Subject: {cert.subject}")
            return cert
        except Exception as e:
            print(f"Error loading certificate: {e}")
        return None

    def generateKey(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
            backend=default_backend()
        )
        with open(self.client_key_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return private_key

    def generateCertRequest(self):
        private_key = self.generateKey()
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.username),
        ])).sign(private_key, hashes.SHA256(), default_backend())
        with open(self.client_csr_path, "wb") as csr_file:
            csr_file.write(csr.public_bytes(serialization.Encoding.PEM))
        return csr.public_bytes(serialization.Encoding.PEM).decode()

    def connect(self):
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()
        channel.queue_declare(queue=self.cert_req_queue)
        self.receive(channel)
        return channel

    def send(self, action, data):
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()
        channel.queue_declare(queue=self.cert_req_queue)
        message = {
            "action": action,
            "data": data
        }
        channel.basic_publish(exchange='', routing_key=self.cert_req_queue, body=json.dumps(message))
        connection.close()

    def receive(self, channel):
        channel.exchange_declare(exchange=self.cert_exchange, exchange_type='fanout')
        result = channel.queue_declare(queue=self.cert_queue_name, exclusive=True)
        queue_name = result.method.queue
        channel.queue_bind(exchange=self.cert_exchange, queue=queue_name)
        channel.basic_consume(queue=queue_name, on_message_callback=self.callback, auto_ack=True)
        channel.start_consuming()

    def callback(self, ch, method, properties, body):
        message = json.loads(body)
        action = message["action"]
        data = message["data"]
        if action == "save_cert":
            cert = self.handle_cert(data)
            if cert:
                with open(f"{self.username}_cert.pem", "wb") as cert_file:
                    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
                print(f"Certificate saved for {self.username}")
        elif action == "verify_cert":
            # Perform certificate verification logic here
            pass

    def request_cert(self):
        cert_data = self.generateCertRequest()
        self.send("request_cert", cert_data)
        self.connect()

    def verify_cert(self):
        cert = self.handle_cert_local(f"{self.username}_cert.pem")
        if cert:
            self.send("verify_cert", cert.public_bytes(serialization.Encoding.PEM).decode())
            self.connect()


