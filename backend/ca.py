import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Directory to store certificates
CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
os.makedirs(CERTS_DIR, exist_ok=True)

class MiniCA:
    def __init__(self):
        self.ca_key_path = os.path.join(CERTS_DIR, "rootCA.key")
        self.ca_cert_path = os.path.join(CERTS_DIR, "rootCA.pem")
        self.revoked_certs = set() # Store serial numbers of revoked certs
        
        # Initialize Root CA if it doesn't exist
        if not os.path.exists(self.ca_key_path) or not os.path.exists(self.ca_cert_path):
            self._generate_root_ca()
        else:
            self._load_root_ca()

    def _generate_root_ca(self):
        # Generate private key
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Self-sign Root CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Danish Industrial Edge"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SIEP Root CA"),
        ])
        
        self.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650) # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(self.ca_key, hashes.SHA256(), default_backend())

        # Save private key
        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save certificate
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def _load_root_ca(self):
        with open(self.ca_key_path, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        with open(self.ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(
                f.read(),
                default_backend()
            )

    def issue_device_cert(self, device_id: str, expiry_days: int = 365) -> tuple[str, str]:
        """
        Generates a private key and signs a certificate for the device.
        Returns (pem_cert, pem_private_key)
        """
        device_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Danish Industrial Edge"),
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        ])
        
        serial_number = x509.random_serial_number()
        
        # Build device certificate signed by root CA
        device_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            device_key.public_key()
        ).serial_number(
            serial_number
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=expiry_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(self.ca_key, hashes.SHA256(), default_backend())

        # Serialize private key
        pem_key = device_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # Serialize certificate
        pem_cert = device_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        # Write to files for reference
        dev_key_path = os.path.join(CERTS_DIR, f"{device_id}.key")
        dev_cert_path = os.path.join(CERTS_DIR, f"{device_id}.crt")
        with open(dev_key_path, "w") as f:
            f.write(pem_key)
        with open(dev_cert_path, "w") as f:
            f.write(pem_cert)
            
        return pem_cert, pem_key

    def verify_device_cert(self, pem_cert: str) -> bool:
        """
        Cryptographically validates the device certificate signature against the Root CA.
        Also checks expiration and CRL.
        """
        try:
            cert = x509.load_pem_x509_certificate(pem_cert.encode('utf-8'), default_backend())
            
            # Check certificate expiration
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                return False
                
            # Check CRL
            if cert.serial_number in self.revoked_certs:
                return False
                
            # Verify signature using Root CA public key
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            return True
        except Exception as e:
            print(f"Cryptographic validation failed: {e}")
            return False

    def revoke_cert(self, pem_cert: str) -> bool:
        try:
            cert = x509.load_pem_x509_certificate(pem_cert.encode('utf-8'), default_backend())
            self.revoked_certs.add(cert.serial_number)
            return True
        except Exception:
            return False

    def revoke_by_serial(self, serial: int) -> bool:
        self.revoked_certs.add(serial)
        return True

    def get_root_ca_pem(self) -> str:
        with open(self.ca_cert_path, "r") as f:
            return f.read()
