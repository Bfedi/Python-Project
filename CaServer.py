from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import os

class CaServer:
    CA_CERT_PATH = "ca_cert.pem"
    CA_KEY_PATH = "ca_key.pem"

    def __init__(self):
        self.cert, self.key = self.generate_or_load()

    def generate_or_load(self):
        if os.path.exists(self.CA_CERT_PATH) and os.path.exists(self.CA_KEY_PATH):
            with open(self.CA_CERT_PATH, "rb") as cert_file, open(self.CA_KEY_PATH, "rb") as key_file:
                cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
                key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        else:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=3072,
                backend=default_backend()
            )

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                x509.datetime.datetime.utcnow()
            ).not_valid_after(
                x509.datetime.datetime.utcnow() + x509.timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            ).sign(key, hashes.SHA256(), default_backend())

            with open(self.CA_CERT_PATH, "wb") as cert_file, open(self.CA_KEY_PATH, "wb") as key_file:
                cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
                key_file.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

        return cert, key

    def handle_cert_req(self, csr_path):
        with open(csr_path, "rb") as csr_file:
            csr = x509.load_pem_x509_csr(csr_file.read(), default_backend())
            cert = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                self.cert.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                x509.datetime.datetime.utcnow()
            ).not_valid_after(
                x509.datetime.datetime.utcnow() + x509.timedelta(days=365)
            ).sign(self.key, hashes.SHA256(), default_backend())

            with open("client_cert.pem", "wb") as cert_file:
                cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    def handle_req(self, req_data, cert):
        csr = x509.load_pem_x509_csr(req_data.encode(), default_backend())
        client_cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            x509.datetime.datetime.utcnow()
        ).not_valid_after(
            x509.datetime.datetime.utcnow() + x509.timedelta(days=365)
        ).sign(self.key, hashes.SHA256(), default_backend())

        return client_cert.public_bytes(serialization.Encoding.PEM).decode()

    def handle_cert(self, data):
        try:
            cert = x509.load_pem_x509_certificate(data.encode(), default_backend())
            return cert
        except Exception as e:
            print(f"Error loading certificate: {e}")
        return None
