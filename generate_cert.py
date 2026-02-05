
import os
import sys
import subprocess
import datetime

def install(package):
    print(f"[*] Installing {package}...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    install('cryptography')
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

def generate_self_signed_cert():
    print("[*] Generating 2048-bit RSA key...")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    print("[*] Generating self-signed certificate for 'localhost'...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Study Hub Dev"),
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
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())

    print("[*] Saving 'localhost-key.pem'...")
    with open("localhost-key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print("[*] Saving 'localhost.pem'...")
    with open("localhost.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("[+] Certificate generation complete!")

if __name__ == "__main__":
    generate_self_signed_cert()
