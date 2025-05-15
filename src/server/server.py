import os
import sys
import time
import uuid
import json
import grpc
import threading
import argparse
import hashlib
import glob
import re
from concurrent import futures
from collections import deque
from google.protobuf.json_format import MessageToDict, ParseDict

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
    
    def get_oldest_audits(self, count=50):
        """
        Get the oldest audits from the mempool, sorted by timestamp.
        
        Args:
            count: Maximum number of audits to return (default: 50)
            
        Returns:
            list: List of FileAudit protobuf messages, sorted by timestamp (oldest first)
        """
        with self.lock:
            # Convert to list and sort by timestamp
            all_audits = list(self.audits)
            sorted_audits = sorted(all_audits, key=lambda a: a.timestamp)
            
            # Return at most count audits
            return sorted_audits[:min(count, len(sorted_audits))]

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

    def __init__(self, mempool, blockchain_stubs, blockchain=None):
        """
        Initialize the servicer.

        Args:
            mempool: Mempool for storing unprocessed requests
            blockchain_stubs: List of stubs for blockchain services
            blockchain: Blockchain instance for checking if audit is included in a block
        """
        self.mempool = mempool
        self.blockchain_stubs = blockchain_stubs
        self.blockchain = blockchain

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

        # Check if this audit is already included in a block
        block_header = None
        blockchain_tx_hash = ""
        if self.blockchain:
            # Search through blocks for this audit ID
            for block in self.blockchain.blocks:
                for audit in block.audits:
                    if audit.req_id == request.req_id:
                        # Found the audit in a block, create block header for response
                        block_header = file_audit_pb2.BlockHeader(
                            block_hash=block.block_hash,
                            block_number=block.block_number,
                            timestamp=block.timestamp,
                            previous_block_hash=block.previous_block_hash,
                            merkle_root=block.merkle_root
                        )
                        blockchain_tx_hash = block.block_hash
                        print(f"Audit {request.req_id} already included in block {block.block_number}")
                        break
                if block_header:
                    break

        # Add the audit to the mempool if not already in a block
        if not block_header:
            # Check if already in mempool to prevent duplicates
            existing_audits = self.mempool.get_audits()
            existing_req_ids = [a.req_id for a in existing_audits]
            if request.req_id not in existing_req_ids:
                self.mempool.add_audit(request)
                # Whisper the audit to other nodes
                self._whisper_audit(request)
            else:
                print(f"Audit {request.req_id} already in mempool, not adding duplicate")

        # Create a response
        # Note: Only including fields defined in the proto
        response = file_audit_pb2.FileAuditResponse(
            req_id=request.req_id, 
            status="success"
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
        data = json.dumps(audit_dict, sort_keys=True, separators=(',', ':'))

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
        for i, stub in enumerate(self.blockchain_stubs):
            try:
                # Get peer address from stub more safely
                target = "unknown"
                try:
                    # Try different ways to get the target address
                    if hasattr(stub, '_channel') and hasattr(stub._channel, 'target'):
                        target = stub._channel.target.decode() if isinstance(stub._channel.target, bytes) else str(stub._channel.target)
                    elif hasattr(stub, '_channel') and hasattr(stub._channel, '_channel') and hasattr(stub._channel._channel, 'target'):
                        target = stub._channel._channel.target.decode() if isinstance(stub._channel._channel.target, bytes) else str(stub._channel._channel.target)
                except Exception:
                    # If all fails, use index in the list
                    pass

                response = stub.WhisperAuditRequest(audit)
                print(
                    f"Whispered audit {audit.req_id} to node {target}. Response: {response.status}"
                )
            except grpc.RpcError as e:
                print(f"Error whispering audit to node {target}: {e.code()}: {e.details()}")


def build_merkle_tree(audit_ids):
    """
    Build a Merkle tree for a list of audit IDs and return the root hash.
    
    Args:
        audit_ids: List of audit request IDs
        
    Returns:
        tuple: (merkle_root, proof_map)
            - merkle_root: The root hash of the Merkle tree
            - proof_map: Dictionary mapping audit IDs to their Merkle proofs
    """
    if not audit_ids:
        return "", {}
        
    # Hash the leaves
    leaves = [hashlib.sha256(audit_id.encode()).hexdigest() for audit_id in audit_ids]
    
    # Store proofs for each leaf
    proof_map = {audit_id: [] for audit_id in audit_ids}
    
    # Build the tree
    current_level = leaves
    while len(current_level) > 1:
        next_level = []
        
        # Ensure even number of nodes at current level for pairing
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])
            
        # Pair nodes and compute parent nodes
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1]
            
            # Create parent hash
            parent = hashlib.sha256((left + right).encode()).hexdigest()
            next_level.append(parent)
            
            # Update proofs for leaves under this node
            for j in range(i*2, min((i+2)*2, len(audit_ids))):
                if j < len(audit_ids):  # Safety check for duplicated last elements
                    leaf_idx = j // 2 if i == 0 else j
                    if leaf_idx < len(audit_ids):
                        sibling = right if j % 2 == 0 else left
                        position = 'right' if j % 2 == 0 else 'left'
                        proof_map[audit_ids[leaf_idx]].append((sibling, position))
                        
        # Move to the next level
        current_level = next_level
    
    # Return the root and proof map
    return current_level[0], proof_map


class Blockchain:
    """Represents a blockchain that stores blocks of audits."""
    
    def __init__(self, blocks_dir="blockchain"):
        """Initialize blockchain and load existing blocks if available.
        
        Args:
            blocks_dir: Directory to store blockchain data
        """
        self.blocks = []  # List of blocks, chronologically ordered
        self.block_map = {}  # Maps block hashes to blocks
        self.blocks_dir = blocks_dir
        self.lock = threading.Lock()
        
        # Create blocks directory if it doesn't exist
        os.makedirs(self.blocks_dir, exist_ok=True)
        
        # Load existing blocks
        self._load_blocks_from_disk()
        
    def _load_blocks_from_disk(self):
        """Load existing blocks from disk on startup."""
        try:
            # Find all block files
            block_files = glob.glob(os.path.join(self.blocks_dir, "block_*.json"))
            
            # Sort files by block number
            block_files.sort(key=lambda f: int(re.search(r'block_(\d+)\.json', f).group(1)))
            
            if not block_files:
                print("No existing blocks found on disk.")
                return
                
            print(f"Found {len(block_files)} blocks on disk.")
            
            # Load blocks
            for block_file in block_files:
                try:
                    with open(block_file, 'r') as f:
                        block_data = json.load(f)
                    
                    # Convert back to protobuf message
                    block = block_chain_pb2.Block()
                    ParseDict(block_data, block)
                    
                    # Add to in-memory blockchain
                    self.blocks.append(block)
                    self.block_map[block.block_hash] = block
                    print(f"Loaded block {block.block_number} with hash {block.block_hash}")
                except Exception as e:
                    print(f"Error loading block file {block_file}: {str(e)}")
            
            print(f"Successfully loaded {len(self.blocks)} blocks from disk")
            
        except Exception as e:
            print(f"Error loading blocks from disk: {str(e)}")
        
    def add_block(self, block):
        """
        Add a validated block to the blockchain.
        
        Args:
            block: Block protobuf message
            
        Returns:
            bool: True if added successfully, False otherwise
        """
        with self.lock:
            # Verify chaining if not genesis block
            if len(self.blocks) > 0:
                if block.previous_block_hash != self.blocks[-1].block_hash:
                    print(f"Block chaining error: Previous hash doesn't match last block")
                    return False
                    
                if block.block_number != len(self.blocks) + 1:
                    print(f"Block number error: Expected {len(self.blocks) + 1}, got {block.block_number}")
                    return False
            
            # Add the block
            self.blocks.append(block)
            self.block_map[block.block_hash] = block
            
            # Save to disk
            self._save_block_to_disk(block)
            
            print(f"Added block {block.block_hash} to blockchain. Chain length: {len(self.blocks)}")
            return True
            
    def _save_block_to_disk(self, block):
        """Save a block to disk.
        
        Args:
            block: Block protobuf message
        """
        try:
            # Convert protobuf to dict for JSON serialization
            block_dict = MessageToDict(block)
            
            # Create filename
            filename = f"block_{block.block_number}.json"
            filepath = os.path.join(self.blocks_dir, filename)
            
            # Write to file
            with open(filepath, 'w') as f:
                json.dump(block_dict, f, indent=2)
                
            print(f"Saved block {block.block_number} to {filepath}")
        except Exception as e:
            print(f"Error saving block to disk: {str(e)}")
            
    def get_latest_block(self):
        """
        Get the latest block in the blockchain.
        
        Returns:
            Block protobuf message or None if chain is empty
        """
        with self.lock:
            if not self.blocks:
                return None
            return self.blocks[-1]
            
    def get_block_by_hash(self, block_hash):
        """
        Get a block by its hash.
        
        Args:
            block_hash: Hash of the block to get
            
        Returns:
            Block protobuf message or None if not found
        """
        with self.lock:
            return self.block_map.get(block_hash, None)
            
    def get_block_by_number(self, block_number):
        """
        Get a block by its number.
        
        Args:
            block_number: Number of the block to get
            
        Returns:
            Block protobuf message or None if not found
        """
        with self.lock:
            if block_number < 1 or block_number > len(self.blocks):
                return None
            return self.blocks[block_number - 1]


class BlockChainServiceServicer(block_chain_pb2_grpc.BlockChainServiceServicer):
    """Servicer for the BlockChainService."""

    def __init__(self, mempool, blockchain=None):
        """
        Initialize the servicer.

        Args:
            mempool: Mempool for storing unprocessed requests
            blockchain: Blockchain for storing finalized blocks
        """
        self.mempool = mempool
        self.blockchain = blockchain if blockchain else Blockchain()

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
                status="failure", error_message="Invalid signature"
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
            request: Block protobuf message
            context: gRPC context

        Returns:
            BlockVoteResponse: Response to the block proposal
        """
        print(f"Received block proposal: {request.id}")

        # Validate the block (simplified for now)
        if not request.audits:
            return block_chain_pb2.BlockVoteResponse(
                vote=False, status="failure", error_message="Block has no audits"
            )

        # Add the block to the blockchain
        if self.blockchain.add_block(request):
            return block_chain_pb2.BlockVoteResponse(vote=True, status="success")
        else:
            return block_chain_pb2.BlockVoteResponse(
                vote=False, status="failure", error_message="Failed to add block"
            )

    def CommitBlock(self, request, context):
        """
        Handle a CommitBlock request.

        Args:
            request: Block protobuf message
            context: gRPC context

        Returns:
            BlockCommitResponse: Response to the block commit
        """
        print(f"Received block commit: {request.id}")

        # Commit the block (simplified for now)
        if self.blockchain.add_block(request):
            return block_chain_pb2.BlockCommitResponse(status="success")
        else:
            return block_chain_pb2.BlockCommitResponse(
                status="failure", error_message="Failed to commit block"
            )

    def GetBlock(self, request, context):
        """
        Handle a GetBlock request.

        Args:
            request: GetBlockRequest protobuf message
            context: gRPC context

        Returns:
            GetBlockResponse: Response with the requested block
        """
        print(f"Received request for block: {request.id}")

        block = self.blockchain.get_block_by_number(request.id)
        if block:
            return block_chain_pb2.GetBlockResponse(block=block, status="success")
        else:
            return block_chain_pb2.GetBlockResponse(
                status="failure", error_message="Block not found"
            )

    def SendHeartbeat(self, request, context):
        """
        Handle a SendHeartbeat request.

        Args:
            request: HeartbeatRequest protobuf message
            context: gRPC context

        Returns:
            HeartbeatResponse: Response to the heartbeat
        """
        print(f"Received heartbeat from {request.from_address}")

        # Process the heartbeat (simplified for now)
        return block_chain_pb2.HeartbeatResponse(status="success")

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
        data = json.dumps(audit_dict, sort_keys=True, separators=(",", ":"))

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


def send_heartbeats(server_address, blockchain_stubs, blockchain, mempool, interval=5):
    """
    Periodically send heartbeats to all connected peers.
    
    Args:
        server_address: Local server address (host:port)
        blockchain_stubs: List of stubs for connected peers
        blockchain: Blockchain instance for getting latest block info
        mempool: Mempool instance for getting size
        interval: Interval in seconds between heartbeats
    """
    print(f"Starting heartbeat sender, sending every {interval} seconds")
    
    while True:
        try:
            # Get latest block info
            latest_block = blockchain.get_latest_block()
            latest_block_id = latest_block.id if latest_block else 0
            
            # Get mempool size
            mempool_size = len(mempool.audits) if hasattr(mempool, 'audits') else 0
            
            # Create heartbeat message - leave current_leader_address empty for simple setup
            heartbeat_request = block_chain_pb2.HeartbeatRequest(
                from_address=server_address,
                current_leader_address="",  # No leader in simple setup
                latest_block_id=latest_block_id,
                mem_pool_size=mempool_size
            )
            
            # Send heartbeat to all peers
            for i, stub in enumerate(blockchain_stubs):
                try:
                    # Get peer address for logging
                    target = "unknown"
                    try:
                        if hasattr(stub, '_channel') and hasattr(stub._channel, 'target'):
                            target = stub._channel.target.decode() if isinstance(stub._channel.target, bytes) else str(stub._channel.target)
                        elif hasattr(stub, '_channel') and hasattr(stub._channel, '_channel') and hasattr(stub._channel._channel, 'target'):
                            target = stub._channel._channel.target.decode() if isinstance(stub._channel._channel.target, bytes) else str(stub._channel._channel.target)
                    except Exception:
                        # If all fails, use index in the list
                        target = f"peer-{i}"
                        
                    # Send the heartbeat with a timeout
                    response = stub.SendHeartbeat(
                        heartbeat_request, 
                        timeout=5  # 5 second timeout
                    )
                    print(f"Sent heartbeat to {target}, response: {response.status}")
                    
                except grpc.RpcError as e:
                    if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                        print(f"Heartbeat timeout for peer {target}")
                    else:
                        print(f"Error sending heartbeat to {target}: {e.code()}: {e.details()}")
                except Exception as e:
                    print(f"Unexpected error sending heartbeat to peer {target}: {str(e)}")
                    
            # Sleep for the interval
            time.sleep(interval)
            
        except Exception as e:
            print(f"Error in heartbeat loop: {str(e)}")
            # Don't crash the heartbeat thread, just wait and retry
            time.sleep(interval)


def serve(port, peer_addresses, slot_duration=10):
    """
    Start the server as a follower node.

    Args:
        port: Port to listen on
        peer_addresses: List of peer addresses
        slot_duration: Not used in follower-only mode
    """
    # Create a mempool
    mempool = Mempool()
    
    # Create blockchain instance
    blockchain = Blockchain()

    # Create stubs for blockchain services
    blockchain_stubs = []
    for address in peer_addresses:
        channel = grpc.insecure_channel(address)
        stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
        blockchain_stubs.append(stub)

    # Create a server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    # Add servicers to the server
    file_audit_servicer = FileAuditServicer(mempool, blockchain_stubs, blockchain)
    file_audit_pb2_grpc.add_FileAuditServiceServicer_to_server(
        file_audit_servicer, server
    )

    blockchain_servicer = BlockChainServiceServicer(mempool, blockchain)
    block_chain_pb2_grpc.add_BlockChainServiceServicer_to_server(
        blockchain_servicer, server
    )

    # Add port
    server.add_insecure_port(f'[::]:{port}')
    
    server.start()
    print(f"Server started on port {port} in FOLLOWER mode")
    print(f"Connected to {len(peer_addresses)} peers: {peer_addresses}")

    # Start heartbeat sender thread
    server_address = f"serhat:{port}"
    heartbeat_thread = threading.Thread(
        target=send_heartbeats, 
        args=(server_address, blockchain_stubs, blockchain, mempool)
    )
    heartbeat_thread.daemon = True
    heartbeat_thread.start()

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
