import os
import sys
import time
import uuid
import json
import grpc
import threading
import argparse
from concurrent import futures
from collections import deque

# Add the parent directory to the path so we can import our modules
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Use standard imports
from src.utils.crypto import verify_signature
from src.generated import (
    common_pb2,
    file_audit_pb2,
    file_audit_pb2_grpc,
    block_chain_pb2,
    block_chain_pb2_grpc,
)


class Mempool:
    """A mempool for storing unprocessed file audit requests."""

    def __init__(self):
        """Initialize the mempool."""
        self.audits = deque()
        self.lock = threading.Lock()

    def add_audit(self, audit):
        """
        Add an audit to the mempool.

        Args:
            audit: FileAudit protobuf message
        """
        with self.lock:
            self.audits.append(audit)
            print(
                f"Added audit {audit.req_id} to mempool. Mempool size: {len(self.audits)}"
            )

    def get_audits(self, count=None):
        """
        Get audits from the mempool.

        Args:
            count: Number of audits to get. If None, get all.

        Returns:
            list: List of FileAudit protobuf messages
        """
        with self.lock:
            if count is None or count >= len(self.audits):
                # Return all audits
                audits = list(self.audits)
                return audits
            else:
                # Return the specified number of audits
                audits = []
                for _ in range(count):
                    if self.audits:
                        audits.append(self.audits.popleft())
                return audits

    def remove_audits(self, audit_ids):
        """
        Remove audits from the mempool.

        Args:
            audit_ids: List of audit IDs to remove
        """
        with self.lock:
            # Create a new deque without the specified audits
            self.audits = deque([a for a in self.audits if a.req_id not in audit_ids])
            print(
                f"Removed {len(audit_ids)} audits from mempool. Mempool size: {len(self.audits)}"
            )


class FileAuditServicer(file_audit_pb2_grpc.FileAuditServiceServicer):
    """Servicer for the FileAuditService."""

    def __init__(self, mempool, blockchain_stubs):
        """
        Initialize the servicer.

        Args:
            mempool: Mempool for storing unprocessed requests
            blockchain_stubs: List of stubs for blockchain services
        """
        self.mempool = mempool
        self.blockchain_stubs = blockchain_stubs

    def SubmitAudit(self, request, context):
        """
        Handle a SubmitAudit request.

        Args:
            request: FileAudit protobuf message
            context: gRPC context

        Returns:
            FileAuditResponse: Response to the client
        """
        print(f"Received audit request: {request.req_id}")

        # Verify the signature
        if not self._verify_signature(request):
            return file_audit_pb2.FileAuditResponse(
                req_id=request.req_id,
                status="failure",
                error_message="Invalid signature",
            )

        # Add the audit to the mempool
        self.mempool.add_audit(request)

        # Whisper the audit to other nodes
        self._whisper_audit(request)

        # Create a response
        response = file_audit_pb2.FileAuditResponse(
            req_id=request.req_id, status="success"
        )

        return response

    def _verify_signature(self, audit):
        """
        Verify the signature of an audit.

        Args:
            audit: FileAudit protobuf message

        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Create a copy of the audit without signature and public_key
        audit_dict = {
            "req_id": audit.req_id,
            "file_info": {
                "file_id": audit.file_info.file_id,
                "file_name": audit.file_info.file_name,
            },
            "user_info": {
                "user_id": audit.user_info.user_id,
                "user_name": audit.user_info.user_name,
            },
            "access_type": audit.access_type,
            "timestamp": audit.timestamp,
        }

        # Create data that was signed
        data = json.dumps(audit_dict, sort_keys=True)

        # Load public key
        try:
            public_key = serialization.load_pem_public_key(
                audit.public_key.encode("utf-8"), backend=default_backend()
            )
        except Exception as e:
            print(f"Error loading public key: {e}")
            return False

        # Verify signature
        return verify_signature(public_key, data, audit.signature)

    def _whisper_audit(self, audit):
        """
        Whisper an audit to other nodes.

        Args:
            audit: FileAudit protobuf message
        """
        for stub in self.blockchain_stubs:
            try:
                response = stub.WhisperAuditRequest(audit)
                print(
                    f"Whispered audit {audit.req_id} to node. Response: {response.status}"
                )
            except grpc.RpcError as e:
                print(f"Error whispering audit: {e.code()}: {e.details()}")


class BlockChainServicer(block_chain_pb2_grpc.BlockChainServiceServicer):
    """Servicer for the BlockChainService."""

    def __init__(self, mempool):
        """
        Initialize the servicer.

        Args:
            mempool: Mempool for storing unprocessed requests
        """
        self.mempool = mempool

    def WhisperAuditRequest(self, request, context):
        """
        Handle a WhisperAuditRequest request.

        Args:
            request: FileAudit protobuf message
            context: gRPC context

        Returns:
            WhisperResponse: Response to the whisper
        """
        print(f"Received whispered audit: {request.req_id}")

        # Verify the signature
        if not self._verify_signature(request):
            return block_chain_pb2.WhisperResponse(
                status="failure", error="Invalid signature"
            )

        # Add the audit to the mempool
        self.mempool.add_audit(request)

        # Create a response
        response = block_chain_pb2.WhisperResponse(status="success")

        return response

    def ProposeBlock(self, request, context):
        """
        Handle a ProposeBlock request.

        Args:
            request: BlockProposal protobuf message
            context: gRPC context

        Returns:
            BlockVoteResponse: Response to the proposal
        """
        print(f"Received block proposal from {request.proposer_id}")

        # TODO: Implement block proposal validation and voting

        # For now, just return success
        return block_chain_pb2.BlockVoteResponse(
            success=True, message="Block proposal accepted"
        )

    def VoteOnBlock(self, request, context):
        """
        Handle a VoteOnBlock request.

        Args:
            request: Vote protobuf message
            context: gRPC context

        Returns:
            BlockVoteResponse: Response to the vote
        """
        print(f"Received vote on block {request.block_id} from {request.validator_id}")

        # TODO: Implement vote handling

        # For now, just return success
        return block_chain_pb2.BlockVoteResponse(success=True, message="Vote accepted")

    def _verify_signature(self, audit):
        """
        Verify the signature of an audit.

        Args:
            audit: FileAudit protobuf message

        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Create a copy of the audit without signature and public_key
        audit_dict = {
            "req_id": audit.req_id,
            "file_info": {
                "file_id": audit.file_info.file_id,
                "file_name": audit.file_info.file_name,
            },
            "user_info": {
                "user_id": audit.user_info.user_id,
                "user_name": audit.user_info.user_name,
            },
            "access_type": audit.access_type,
            "timestamp": audit.timestamp,
        }

        # Create data that was signed
        data = json.dumps(audit_dict, sort_keys=True)

        # Load public key
        try:
            public_key = serialization.load_pem_public_key(
                audit.public_key.encode("utf-8"), backend=default_backend()
            )
        except Exception as e:
            print(f"Error loading public key: {e}")
            return False

        # Verify signature
        return verify_signature(public_key, data, audit.signature)


def serve(port, peer_addresses):
    """
    Start the server.

    Args:
        port: Port to listen on
        peer_addresses: List of peer addresses
    """
    # Create a mempool
    mempool = Mempool()

    # Create stubs for blockchain services
    blockchain_stubs = []
    for address in peer_addresses:
        channel = grpc.insecure_channel(address)
        stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
        blockchain_stubs.append(stub)

    # Create a server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    # Add servicers to the server
    file_audit_servicer = FileAuditServicer(mempool, blockchain_stubs)
    file_audit_pb2_grpc.add_FileAuditServiceServicer_to_server(
        file_audit_servicer, server
    )

    blockchain_servicer = BlockChainServicer(mempool)
    block_chain_pb2_grpc.add_BlockChainServiceServicer_to_server(
        blockchain_servicer, server
    )

    # Start the server
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"Server started on port {port}")
    print(f"Connected to {len(peer_addresses)} peers: {peer_addresses}")

    try:
        while True:
            time.sleep(86400)  # Sleep for a day
    except KeyboardInterrupt:
        server.stop(0)
        print("Server stopped")


def main():
    """Main function for the server."""
    parser = argparse.ArgumentParser(description="File Audit Server")
    parser.add_argument("--port", type=int, default=50051, help="Port to listen on")
    parser.add_argument("--peers", nargs="*", default=[], help="Peer addresses")

    args = parser.parse_args()

    serve(args.port, args.peers)


if __name__ == "__main__":
    main()
