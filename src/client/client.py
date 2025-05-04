import os
import sys
import uuid
import grpc
import time
import argparse
from cryptography.hazmat.primitives import serialization

# Add the parent directory to the path so we can import our modules
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

# Use standard imports
from src.utils.crypto import generate_key_pair, sign_data, get_public_key_pem
from src.generated import common_pb2, file_audit_pb2, file_audit_pb2_grpc


class FileAuditClient:
    """Client for sending file audit requests."""

    def __init__(self, server_address, private_key_path=None, public_key_path=None):
        """
        Initialize the client.

        Args:
            server_address: Address of the server (host:port)
            private_key_path: Path to the private key file
            public_key_path: Path to the public key file
        """
        self.server_address = server_address
        self.channel = grpc.insecure_channel(server_address)
        self.stub = file_audit_pb2_grpc.FileAuditServiceStub(self.channel)

        # Generate or load keys
        self.private_key, self.public_key = generate_key_pair(
            private_key_path, public_key_path
        )

        print(f"Connected to server at {server_address}")
        if private_key_path:
            print(f"Using private key from {private_key_path}")
        else:
            print("Generated new key pair")

    def create_file_audit(self, file_path, user_id, user_name, access_type):
        """
        Create a file audit record.

        Args:
            file_path: Path to the file being audited
            user_id: ID of the user performing the action
            user_name: Name of the user performing the action
            access_type: Type of access (READ, WRITE, UPDATE, DELETE)

        Returns:
            FileAudit: The created file audit record
        """
        # Get file info
        try:
            file_id = str(os.stat(file_path).st_ino)  # inode number
        except FileNotFoundError:
            file_id = "unknown"

        file_name = os.path.basename(file_path)

        # Create file info
        file_info = common_pb2.FileInfo(file_id=file_id, file_name=file_name)

        # Create user info
        user_info = common_pb2.UserInfo(user_id=user_id, user_name=user_name)

        # Map string access type to enum
        access_type_map = {
            "READ": common_pb2.AccessType.READ,
            "WRITE": common_pb2.AccessType.WRITE,
            "UPDATE": common_pb2.AccessType.UPDATE,
            "DELETE": common_pb2.AccessType.DELETE,
            "UNKNOWN": common_pb2.AccessType.UNKNOWN,
        }

        # Default to UNKNOWN if not found
        access_type_enum = access_type_map.get(
            access_type.upper(), common_pb2.AccessType.UNKNOWN
        )

        # Create audit record without signature and public key
        audit = {
            "req_id": str(uuid.uuid4()),
            "file_info": {"file_id": file_id, "file_name": file_name},
            "user_info": {"user_id": user_id, "user_name": user_name},
            "access_type": access_type_enum,
            "timestamp": int(time.time()),
        }

        # Create data to sign (all fields except signature and public_key)
        import json

        data_to_sign = json.dumps(audit, sort_keys=True)

        # Sign the data
        signature = sign_data(self.private_key, data_to_sign)

        # Get public key in PEM format
        public_key_pem = get_public_key_pem(self.public_key)

        # Create the FileAudit protobuf message
        file_audit = common_pb2.FileAudit(
            req_id=audit["req_id"],
            file_info=file_info,
            user_info=user_info,
            access_type=access_type_enum,
            timestamp=audit["timestamp"],
            signature=signature,
            public_key=public_key_pem,
        )

        return file_audit

    def submit_audit(self, file_audit):
        """
        Submit a file audit record to the server.

        Args:
            file_audit: FileAudit protobuf message

        Returns:
            FileAuditResponse: The server's response
        """
        try:
            response = self.stub.SubmitAudit(file_audit)
            return response
        except grpc.RpcError as e:
            print(f"RPC error: {e.code()}: {e.details()}")
            return None

    def close(self):
        """Close the gRPC channel."""
        self.channel.close()


def main():
    """Main function for the client."""
    parser = argparse.ArgumentParser(description="File Audit Client")
    parser.add_argument("--server", default="localhost:50051", help="Server address")
    parser.add_argument("--private-key", help="Path to private key file")
    parser.add_argument("--public-key", help="Path to public key file")
    parser.add_argument("--file", required=True, help="File to audit")
    parser.add_argument("--user-id", default=str(os.getuid()), help="User ID")
    parser.add_argument("--user-name", default=os.getlogin(), help="User name")
    parser.add_argument(
        "--access-type",
        choices=["READ", "WRITE", "UPDATE", "DELETE"],
        default="READ",
        help="Access type",
    )

    args = parser.parse_args()

    # Create client
    client = FileAuditClient(args.server, args.private_key, args.public_key)

    # Create and submit audit
    file_audit = client.create_file_audit(
        args.file, args.user_id, args.user_name, args.access_type
    )

    print(f"Submitting audit for {args.file} with access type {args.access_type}")
    response = client.submit_audit(file_audit)

    if response:
        print(f"Audit submitted successfully: {response.status}")
        if response.blockchain_tx_hash:
            print(f"Blockchain transaction hash: {response.blockchain_tx_hash}")

    # Close client
    client.close()


if __name__ == "__main__":
    main()
