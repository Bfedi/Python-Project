from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

"""Le code ci-dessous est pris des exemples de cryptography.io"""


#Generer RSA paire
def Keygen_rsa():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    with open("key/to/store/key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    return key

#Generer une Certificate Signing Request (CSR)
def gen_csr(key):

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "TN"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "mysite.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mysite.com"),
        x509.NameAttribute(NameOID.SURNAME, "mysite.com"),
        x509.NameAttribute(NameOID.USER_ID, "mysite.com"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName("mysite.com"),
            x509.DNSName("www.mysite.com"),
            x509.DNSName("subdomain.mysite.com"),
        ]),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256())
    # Write our CSR out to disk.
    with open("request/to/store/csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr


