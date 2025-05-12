import os
import sys
import uuid
import grpc
import time
import argparse
import socket
from cryptography.hazmat.primitives import serialization

# Add the parent directory to the path so we can import our modules
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))


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

        
        data_to_sign = json.dumps(audit, sort_keys=True, separators=(",", ":"))
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
            # If there's a blockchain transaction hash, print it
            if hasattr(response, 'blockchain_tx_hash') and response.blockchain_tx_hash:
                print(f"Blockchain transaction hash: {response.blockchain_tx_hash}")
            if hasattr(response, 'block_header') and response.block_header.block_hash:
                print(f"Included in block: {response.block_header.block_hash}")
                print(f"Block number: {response.block_header.block_number}")
            return response
        except grpc.RpcError as e:
            print(f"RPC error: {e.code()}: {e.details()}")
            return None

    def close(self):
        """Close the gRPC channel."""
        self.channel.close()


def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        # Connect to a public address (doesn't actually establish a connection)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("0.0.0.0", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
    


def run_client(server_address, file_path, num_audits=1, delay=2):
    """Run a client to submit file audits."""
    # Create keys directory if it doesn't exist
    os.makedirs("keys", exist_ok=True)
    
    # Define key paths
    private_key_path = os.path.abspath("keys/private_key.pem")
    public_key_path = os.path.abspath("keys/public_key.pem")
    
    # Generate keys if they don't exist (you may need to implement this)
    if not (os.path.exists(private_key_path) and os.path.exists(public_key_path)):
        print("Generating new key pair...")
        # Call your key generation function here if available
        # Or use subprocess to call an external script
    
    # Get user info
    try:
        user_id = str(os.getuid())
    except AttributeError:
        # Windows doesn't have getuid
        user_id = "1000"

    try:
        user_name = os.getlogin()
    except Exception:
        user_name = "user"
    
    print(f"Submitting {num_audits} audit(s) for file {file_path} to server {server_address}")
    
    # Run the required number of audits
    for i in range(num_audits):
        if i > 0:
            print(f"Waiting {delay} seconds before next audit...")
            time.sleep(delay)
        
        # Determine file name for this audit
        current_file = f"{file_path}_{i}" if num_audits > 1 else file_path
        
        print(f"Audit {i+1}/{num_audits}: Submitting audit for {current_file}")
        
        # Call the underlying client implementation using the FileAuditClient class
        from src.client.client import FileAuditClient
        
        # Create client and submit audit
        client = FileAuditClient(server_address, private_key_path, public_key_path)
        file_audit = client.create_file_audit(current_file, user_id, user_name, "READ")
        response = client.submit_audit(file_audit)
        
        if response:
            print(f"Audit submitted successfully: {response.status}")
            if hasattr(response, 'blockchain_tx_hash') and response.blockchain_tx_hash:
                print(f"Blockchain transaction hash: {response.blockchain_tx_hash}")
        else:
            print("Failed to submit audit")
        
        client.close()

def generate_proto():
    """Generate Python code from proto files."""
    print("Generating Python code from proto files...")
    # Import the generate_proto module
    import importlib.util
    spec = importlib.util.spec_from_file_location("generate_proto", "generate_proto.py")
    generate_proto_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generate_proto_module)

    # Call the generate_proto function
    generate_proto_module.generate_proto()
    print("Done generating Python code.")

def main():
    """Main function for client operations."""
    parser = argparse.ArgumentParser(description="Submit file audits to a server")
    parser.add_argument("--file", default="testfile.txt", help="File to audit")
    parser.add_argument("--server-address", default="169.254.13.100:50051", 
                        help="Address of the audit server")
    parser.add_argument("--num-audits", type=int, default=1,
                        help="Number of audits to submit")
    parser.add_argument("--client-delay", type=int, default=2,
                        help="Seconds between client audit submissions")

    args = parser.parse_args()

    # Generate Python code from proto files
    generate_proto()
    
    # Run the client with the provided arguments
    run_client(
        server_address=args.server_address,
        file_path=args.file,
        num_audits=args.num_audits,
        delay=args.client_delay
    )

if __name__ == "__main__":
    main()