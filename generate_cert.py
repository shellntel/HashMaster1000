import os
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from datetime import datetime, timedelta

current_time = datetime.fromtimestamp(time.time())
load_dotenv()

# Generate a private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)

# Define subject and issuer using environment variables
# Debug: Print loaded environment variables
print("Environment Variables Loaded:")
for var in [
    "COUNTRY_NAME",
    "STATE_OR_PROVINCE_NAME",
    "LOCALITY_NAME",
    "ORGANIZATION_NAME",
    "COMMON_NAME",
]:
    print(f"{var}: {os.getenv(var)}")

# Define subject and issuer using environment variables
subject = issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, os.getenv("COUNTRY_NAME", "US")),
        x509.NameAttribute(
            NameOID.STATE_OR_PROVINCE_NAME,
            os.getenv("STATE_OR_PROVINCE_NAME", "DefaultState"),
        ),
        x509.NameAttribute(
            NameOID.LOCALITY_NAME, os.getenv("LOCALITY_NAME", "DefaultCity")
        ),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME, os.getenv("ORGANIZATION_NAME", "DefaultOrg")
        ),
        x509.NameAttribute(NameOID.COMMON_NAME, os.getenv("COMMON_NAME", "localhost")),
    ]
)

print("Subject and Issuer Created:")
for attribute in subject:
    print(f"  {attribute.oid}: {attribute.value}")

certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(current_time)
    .not_valid_after(current_time + timedelta(days=365))  # Certificate valid for 1 year
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    )
    .sign(private_key, hashes.SHA256(), default_backend())
)

# Write private key and certificate to files
with open("key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
    )

with open("cert.pem", "wb") as f:
    f.write(certificate.public_bytes(Encoding.PEM))

print("Self-signed certificate and key have been created as cert.pem and key.pem.")
