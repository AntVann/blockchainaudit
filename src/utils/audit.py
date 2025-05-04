import time
import uuid
import json
import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Add the parent directory to the path so we can import our modules
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from src.utils.crypto import sign_data, verify_signature, get_public_key_pem


def create_file_audit(
    file_path, user_id, user_name, access_type, private_key, public_key
):
    """
    Create a file audit record.

    Args:
        file_path: Path to the file being audited
        user_id: ID of the user performing the action
        user_name: Name of the user performing the action
        access_type: Type of access (READ, WRITE, UPDATE, DELETE)
        private_key: RSA private key for signing
        public_key: RSA public key for verification

    Returns:
        dict: File audit record
    """
    # Get file info
    try:
        file_id = str(os.stat(file_path).st_ino)  # inode number
    except FileNotFoundError:
        file_id = "unknown"

    file_name = os.path.basename(file_path)

    # Create audit record
    audit = {
        "req_id": str(uuid.uuid4()),
        "file_info": {"file_id": file_id, "file_name": file_name},
        "user_info": {"user_id": user_id, "user_name": user_name},
        "access_type": access_type,
        "timestamp": int(time.time()),
    }

    # Create data to sign (all fields except signature and public_key)
    data_to_sign = json.dumps(audit, sort_keys=True)

    # Sign the data
    signature = sign_data(private_key, data_to_sign)

    # Add signature and public key
    audit["signature"] = signature
    audit["public_key"] = get_public_key_pem(public_key)

    return audit


def verify_file_audit(audit):
    """
    Verify a file audit record.

    Args:
        audit: File audit record

    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Create a copy of the audit without signature and public_key
    audit_copy = audit.copy()
    signature = audit_copy.pop("signature", None)
    public_key_pem = audit_copy.pop("public_key", None)

    if not signature or not public_key_pem:
        return False

    # Load public key
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"), backend=default_backend()
        )
    except Exception:
        return False

    # Create data that was signed
    data = json.dumps(audit_copy, sort_keys=True)

    # Verify signature
    return verify_signature(public_key, data, signature)
