import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


def generate_key_pair(private_key_path=None, public_key_path=None):
    """
    Generate an RSA key pair or load existing keys.

    Args:
        private_key_path: Path to save or load the private key
        public_key_path: Path to save or load the public key

    Returns:
        tuple: (private_key, public_key)
    """
    # If paths are provided and keys exist, load them
    if private_key_path and os.path.exists(private_key_path):
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

        if public_key_path and os.path.exists(public_key_path):
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(), backend=default_backend()
                )
        else:
            # Derive public key from private key
            public_key = private_key.public_key()

        return private_key, public_key

    # Generate new key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save keys if paths are provided
    if private_key_path:
        with open(private_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    if public_key_path:
        with open(public_key_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    return private_key, public_key


def sign_data(private_key, data):
    """
    Sign data with a private key.

    Args:
        private_key: RSA private key
        data: Data to sign (bytes)

    Returns:
        str: Base64-encoded signature
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key, data, signature):
    """
    Verify a signature with a public key.

    Args:
        public_key: RSA public key
        data: Original data (bytes)
        signature: Base64-encoded signature

    Returns:
        bool: True if signature is valid, False otherwise
    """

    try:
        public_key.verify(base64.b64decode(signature),
                        data.encode("utf-8"),
                        padding.PKCS1v15(), 
                        hashes.SHA256())
        return True
    except Exception:
        return False


def get_public_key_pem(public_key):
    """
    Get the PEM representation of a public key.

    Args:
        public_key: RSA public key

    Returns:
        str: PEM-encoded public key
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")
