"""
Server implementation for blockchain audit system with leader election support.

Leader Election Process:
1. When a server starts or detects that the current leader is missing heartbeats,
   it triggers an election by calling TriggerElection on all peers.
   
2. Criteria for accepting an election request:
   - The term number must be greater than the current term.
   - The server hasn't voted for someone else in the current term.

3. Tie-breaking criteria (in order):
   - Server with the most blocks (highest latest_block_id)
   - Server with the largest mempool
   - String comparison of server addresses

4. After winning an election (getting majority votes), the server calls 
   NotifyLeadership on all peers to announce its leadership.

5. Heartbeat mechanism is used to detect leader failures. If N consecutive 
   heartbeats are missed from the leader, a new election is triggered.
"""

import os
import sys
import time
import uuid
import socket
import json
import grpc
import threading
import argparse
import hashlib
import glob
import re
import logging
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
from src.utils.config import load_config, get_peer_addresses, get_server_config
from src.generated import (
    common_pb2,
    file_audit_pb2,
    file_audit_pb2_grpc,
    block_chain_pb2,
    block_chain_pb2_grpc,
)

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class Mempool:
    """A mempool for storing unprocessed file audit requests."""

    def __init__(self):
        """Initialize the mempool."""
        self.audits = deque()
        self.lock = threading.Lock()

    def add_audit(self, audit):
    
        with self.lock:
            self.audits.append(audit)
            print(
                f"Added audit {audit.req_id} to mempool. Mempool size: {len(self.audits)}"
            )

    def get_audits(self, count=None):
        
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
        
        with self.lock:
            # Convert to list and sort by timestamp
            all_audits = list(self.audits)
            sorted_audits = sorted(all_audits, key=lambda a: a.timestamp)
            
            # Return at most count audits
            return sorted_audits[:min(count, len(sorted_audits))]

    def remove_audits(self, audit_ids):
        
        with self.lock:
            # Count how many audits will actually be removed
            audits_before = len(self.audits)
            # Create a new deque without the specified audits
            self.audits = deque([a for a in self.audits if a.req_id not in audit_ids])
            audits_after = len(self.audits)
            audits_removed = audits_before - audits_after
            
            if audits_removed > 0:
                print(f"Removed {audits_removed} audits from mempool. Mempool size: {audits_after}")
            else:
                print(f"No matching audits found to remove. Mempool size remains: {audits_after}")


class FileAuditServicer(file_audit_pb2_grpc.FileAuditServiceServicer):
    """Servicer for the FileAuditService."""

    def __init__(self, mempool, blockchain_stubs, blockchain=None):
        
        self.mempool = mempool
        self.blockchain_stubs = blockchain_stubs
        self.blockchain = blockchain

    def SubmitAudit(self, request, context):
        
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
                            block_hash=block.hash,
                            block_number=block.id,
                            timestamp=getattr(block, 'timestamp', 0),  # Use timestamp if exists, 0 otherwise
                            previous_block_hash=block.previous_hash,
                            merkle_root=block.merkle_root
                        )
                        blockchain_tx_hash = block.hash
                        print(f"Audit {request.req_id} already included in block {block.id}")
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
        response = file_audit_pb2.FileAuditResponse(
            req_id=request.req_id, 
            status="success"
        )

        return response

    def _verify_signature(self, audit):
        
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
                    self.block_map[block.hash] = block
                    print(f"Loaded block {block.id} with hash {block.hash}")
                except Exception as e:
                    print(f"Error loading block file {block_file}: {str(e)}")
            
            print(f"Successfully loaded {len(self.blocks)} blocks from disk")
            
        except Exception as e:
            print(f"Error loading blocks from disk: {str(e)}")
        
    def add_block(self, block):
        """
        Add a validated block to the blockchain.
        
        
        """
        with self.lock:
            # Check if this is the genesis block (id=0)
            if len(self.blocks) == 0:
                if block.id != 0:
                    print(f"Genesis block should have id=0, got {block.id}")
                    return False
            # Verify chaining for non-genesis blocks
            else:
                if block.previous_hash != self.blocks[-1].hash:
                    print(f"Block chaining error: Previous hash doesn't match last block")
                    return False
                    
                if block.id != self.blocks[-1].id + 1:
                    print(f"Block number error: Expected {self.blocks[-1].id + 1}, got {block.id}")
                    return False
            
            # Add the block
            self.blocks.append(block)
            self.block_map[block.hash] = block
            
            # Save to disk
            self._save_block_to_disk(block)
            
            print(f"Added block {block.hash} to blockchain. Chain length: {len(self.blocks)}")
            return True
            
    def _save_block_to_disk(self, block):
        """Save a block to disk.
        

        """
        try:
            # Convert protobuf to dict for JSON serialization
            block_dict = MessageToDict(block)
            
            # Create filename
            filename = f"block_{block.id}.json"
            filepath = os.path.join(self.blocks_dir, filename)
            
            # Write to file
            with open(filepath, 'w') as f:
                json.dump(block_dict, f, indent=2)
                
            print(f"Saved block {block.id} to {filepath}")
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
        
        """
        with self.lock:
            # Make sure we're looking up by the correct field
            result = self.block_map.get(block_hash, None)
            if result is None and block_hash:
                # Try to find the block by iterating through all blocks if not found in the map
                for block in self.blocks:
                    if block.hash == block_hash:
                        return block
            return result
            
    def get_block_by_number(self, block_number):
        """
        Get a block by its number.
        
        """
        with self.lock:
            # First try to find it by position in the array
            if 0 <= block_number < len(self.blocks):
                if self.blocks[block_number].id == block_number:
                    return self.blocks[block_number]
                    
            # If not found, search through all blocks by id
            for block in self.blocks:
                if block.id == block_number:
                    return block
            
            # Block not found
            return None


class BlockChainServiceServicer(block_chain_pb2_grpc.BlockChainServiceServicer):
    """Servicer for the BlockChainService."""

    def __init__(self, mempool, blockchain=None):
        """
        Initialize the servicer.

        """
        self.mempool = mempool
        self.blockchain = blockchain if blockchain else Blockchain()
        self.current_term = 0
        self.current_leader_address = ""
        self.voted_for = None  # Keep track of who this server voted for in the current term
        self.heartbeat_timestamps = {}  # Map of server address to last heartbeat timestamp
        self.is_leader = False  # Whether this server is the leader
        self.peer_latest_block_ids = {}  # Map of peer address to their latest block ID

    def WhisperAuditRequest(self, request, context):
        """
        Handle a WhisperAuditRequest request.

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

        """
        print(f"Received block proposal: {request.id}")

        # Check if this block has already been added (by hash)
        existing_block = self.blockchain.get_block_by_hash(request.hash)
        if existing_block:
            print(f"Block {request.id} with hash {request.hash} already exists in the blockchain")
            
            # Even when the block already exists, clean up mempool
            # This ensures consistent behavior between propose and commit
            if request.audits:
                audit_ids = [audit.req_id for audit in request.audits]
                # Check if these audits are actually in the mempool before logging the warning
                audits_in_mempool = 0
                with self.mempool.lock:
                    audits_in_mempool = sum(1 for a in self.mempool.audits if a.req_id in audit_ids)
                
                if audits_in_mempool > 0:
                    print(f"Block {request.id} already exists, removing {audits_in_mempool} out of {len(audit_ids)} audits from mempool")
                    self.mempool.remove_audits(audit_ids)
                else:
                    print(f"Block {request.id} already exists, no matching audits found in mempool")
                
            return block_chain_pb2.BlockVoteResponse(vote=True, status="success")

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

        """
        print(f"Received block commit: {request.id}")

        # Check if this block has already been added (by hash)
        existing_block = self.blockchain.get_block_by_hash(request.hash)
        if existing_block:
            print(f"Block {request.id} with hash {request.hash} already exists in the blockchain")
            
            # Even if block already exists, make sure to clear the audits from mempool
            # to handle the case of duplicate commit requests
            if request.audits:
                audit_ids = [audit.req_id for audit in request.audits]
                # Check if these audits are actually in the mempool before logging the warning
                audits_in_mempool = 0
                with self.mempool.lock:
                    audits_in_mempool = sum(1 for a in self.mempool.audits if a.req_id in audit_ids)
                
                if audits_in_mempool > 0:
                    print(f"Block {request.id} already exists, removing {audits_in_mempool} out of {len(audit_ids)} audits from mempool")
                    self.mempool.remove_audits(audit_ids)
                else:
                    print(f"Block {request.id} already exists, no matching audits found in mempool")
                
            return block_chain_pb2.BlockCommitResponse(status="success")
        
        # If block doesn't already exist, commit it
        if self.blockchain.add_block(request):
            # Clear only the audits that are in the block from the mempool
            if request.audits:
                # Extract audit IDs from the block
                audit_ids = [audit.req_id for audit in request.audits]
                print(f"Removing {len(audit_ids)} audits from mempool that are included in block {request.id}")
                # Remove these audits from the mempool
                self.mempool.remove_audits(audit_ids)
            
            return block_chain_pb2.BlockCommitResponse(status="success")
        else:
            return block_chain_pb2.BlockCommitResponse(
                status="failure", error_message="Failed to commit block"
            )

    def GetBlock(self, request, context):
        """
        Handle a GetBlock request.
        """
        print(f"Received request for block: {request.id}")

        # Get the latest block ID for error reporting
        latest_block = self.blockchain.get_latest_block()
        latest_block_id = latest_block.id if latest_block else -1

        block = self.blockchain.get_block_by_number(request.id)
        if block:
            return block_chain_pb2.GetBlockResponse(block=block, status="success")
        else:
            # Include the highest block ID in the error message to help with syncing
            return block_chain_pb2.GetBlockResponse(
                status="failure", 
                error_message=f"Block not found. The highest block ID is {latest_block_id}"
            )

    def SendHeartbeat(self, request, context):
        logger.info(f"Received heartbeat from {request.from_address}")
        
        # Store the peer's latest block ID for block sync monitoring
        if request.latest_block_id > 0 and request.from_address:
            # Update our records of which peers have which blocks
            self.peer_latest_block_ids[request.from_address] = request.latest_block_id
            logger.debug(f"Updated block info for {request.from_address}, latest block: {request.latest_block_id}")

        # Check if this is a special request to get mempool contents
        if request.from_address == "LEADER_GET_MEMPOOL":
            # This is a special request from the leader to get mempool contents

            # Get the requested number of audits from the mempool
            max_audits = request.mem_pool_size if request.mem_pool_size > 0 else 50
            pending_audits = self.mempool.get_oldest_audits(count=max_audits)

            # Serialize audits list to JSON in error_message field (no proto change)
            try:
                from google.protobuf.json_format import MessageToDict
                import json
                audits_json = [MessageToDict(a) for a in pending_audits]
                return block_chain_pb2.HeartbeatResponse(
                    status="success",
                    error_message=json.dumps(audits_json)
                )
            except Exception as e:
                logger.error(f"Error serializing mempool audits: {e}")
                return block_chain_pb2.HeartbeatResponse(status="failure", error_message=str(e))

        # Update current leader from heartbeat if provided
        if request.current_leader_address and not self.current_leader_address:
            logger.info(f"Learning about leader {request.current_leader_address} from heartbeat")
            self.current_leader_address = request.current_leader_address
        
        # Get our latest block for the response
        latest_block = self.blockchain.get_latest_block()
        our_latest_block_id = latest_block.id if latest_block else 0
        
        # Process the heartbeat
        return block_chain_pb2.HeartbeatResponse(status="success")

    def _verify_signature(self, audit):
        """
        Verify the signature of an audit.

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

    def TriggerElection(self, request, context):
        """
        Handle a TriggerElection request.

        """
        logger.info(f"Received election request from {request.address} for term {request.term}")
        
        # Initialize response
        vote_granted = False
        
        # Check if the term is valid (must be >= our current term)
        if request.term < self.current_term:
            logger.info(f"Rejecting vote for {request.address}: term {request.term} < current term {self.current_term}")
            return block_chain_pb2.TriggerElectionResponse(
                vote=False, 
                term=self.current_term,
                status="failure", 
                error_message=f"Term {request.term} is less than current term {self.current_term}"
            )
        
        # If term is greater, update our term
        if request.term > self.current_term:
            logger.info(f"Updating local term from {self.current_term} to {request.term}")
            self.current_term = request.term
            self.voted_for = None  # Reset vote for the new term
        
        # Check if we've already voted for someone else in this term
        if self.voted_for is not None and self.voted_for != request.address:
            logger.info(f"Rejecting vote for {request.address}: already voted for {self.voted_for} in term {self.current_term}")
            return block_chain_pb2.TriggerElectionResponse(
                vote=False, 
                term=self.current_term,
                status="failure", 
                error_message=f"Already voted for {self.voted_for} in term {self.current_term}"
            )
        
        # If we got here, we can vote for this candidate
        # The actual voting logic (tie breakers) will be applied by the caller
        self.voted_for = request.address
        vote_granted = True
        
        logger.info(f"Voting for {request.address} in term {self.current_term}")
        return block_chain_pb2.TriggerElectionResponse(
            vote=vote_granted, 
            term=self.current_term,
            status="success"
        )

    def NotifyLeadership(self, request, context):
        """
        Handle a NotifyLeadership request.
        """
        logger.info(f"Received leadership notification from {request.address}")
        
        # Update current leader
        self.current_leader_address = request.address
        logger.info(f"Updated leader to {self.current_leader_address}")
        
        return block_chain_pb2.NotifyLeadershipResponse(status="success")


def send_heartbeats(server_address, peer_stub_map, blockchain, mempool, blockchain_servicer, interval=5, missing_heartbeat_threshold=3):
    """
    Periodically send heartbeats to all connected peers and handle leader election.
 
    """
    logger.info(f"Starting heartbeat sender, sending every {interval} seconds to {len(peer_stub_map)} peers")
    
    # Initialize heartbeat tracking
    last_heartbeat_times = {}  # Maps peer address to last heartbeat timestamp
    current_term = 0  # Start with term 0
    leader_missing_count = 0  # Counter for missing leader heartbeats
    
    while True:
        try:
            # Get latest block info
            latest_block = blockchain.get_latest_block()
            latest_block_id = latest_block.id if latest_block else 0
            
            # Get mempool size
            mempool_size = len(mempool.audits) if hasattr(mempool, 'audits') else 0
            
            # Create heartbeat message with current leader address
            heartbeat_request = block_chain_pb2.HeartbeatRequest(
                from_address=server_address,
                current_leader_address=blockchain_servicer.current_leader_address,
                latest_block_id=latest_block_id,
                mem_pool_size=mempool_size
            )
            
            # Send heartbeat to all peers
            current_time = time.time()
            for peer_address, stub in peer_stub_map.items():
                try:
                    # Use the peer address we already know from the map
                    target = peer_address
                        
                    # Send the heartbeat with a timeout
                    response = stub.SendHeartbeat(
                        heartbeat_request, 
                        timeout=5  # 5 second timeout
                    )
                    logger.info(f"Sent heartbeat to {target}, response: {response.status}")
                    
                    # Update last heartbeat time for this peer
                    last_heartbeat_times[target] = current_time
                    
                except grpc.RpcError as e:
                    if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                        logger.warning(f"Heartbeat timeout for peer {target}")
                    else:
                        logger.error(f"Error sending heartbeat to {target}: {e.code()}: {e.details()}")
                except Exception as e:
                    logger.error(f"Unexpected error sending heartbeat to peer {target}: {str(e)}")
            
            # Check for missing heartbeats and potentially trigger election
            if blockchain_servicer.current_leader_address:
                # If there's a known leader but we haven't heard from them
                leader_address = blockchain_servicer.current_leader_address
                if leader_address in last_heartbeat_times:
                    last_leader_time = last_heartbeat_times[leader_address]
                    if current_time - last_leader_time > interval * missing_heartbeat_threshold:
                        leader_missing_count += 1
                        logger.warning(f"Leader {leader_address} missed heartbeat, count: {leader_missing_count}")
                        
                        if leader_missing_count >= missing_heartbeat_threshold:
                            # Leader is considered dead, trigger election
                            logger.info(f"Leader {leader_address} is dead, triggering election")
                            trigger_election(server_address, peer_stub_map, blockchain, mempool, current_term + 1, blockchain_servicer)
                            leader_missing_count = 0  # Reset counter
                    else:
                        leader_missing_count = 0  # Reset counter if we got a recent heartbeat
            elif not blockchain_servicer.current_leader_address:
                # No leader known, trigger election
                logger.info("No leader known, triggering election")
                trigger_election(server_address, peer_stub_map, blockchain, mempool, current_term + 1, blockchain_servicer)
            
            # Sleep for the interval
            time.sleep(interval)
            
        except Exception as e:
            logger.error(f"Error in heartbeat loop: {str(e)}")
            # Don't crash the heartbeat thread, just wait and retry
            time.sleep(interval)


def trigger_election(server_address, peer_stub_map, blockchain, mempool, term, blockchain_servicer=None):
    """
    Trigger an election and try to become the leader.
    
    """
    logger.info(f"Starting election for term {term}")
    
    # Get latest block info and mempool size for tie-breaking
    latest_block = blockchain.get_latest_block()
    latest_block_id = latest_block.id if latest_block else 0
    mempool_size = len(mempool.audits) if hasattr(mempool, 'audits') else 0
    
    # Send TriggerElection to all peers
    votes = 0
    election_request = block_chain_pb2.TriggerElectionRequest(
        term=term,
        address=server_address
    )
    
    reachable_peers = 0
    for peer_address, stub in peer_stub_map.items():
        try:
            logger.info(f"Requesting vote from {peer_address} for term {term}")
            response = stub.TriggerElection(
                election_request, 
                timeout=5  # 5 second timeout
            )
            
            logger.info(f"Vote from {peer_address}: {response.vote}, term: {response.term}")
            
            # Update our term if the peer has a higher term
            if response.term > term:
                logger.info(f"Peer has higher term {response.term} > {term}, abandoning election")
                return False
                
            reachable_peers += 1
            # Count the vote
            if response.vote:
                votes += 1
                
        except grpc.RpcError as e:
            logger.error(f"Error requesting vote from {peer_address}: {e.code()}: {e.details()}")
        except Exception as e:
            logger.error(f"Unexpected error requesting vote from {peer_address}: {str(e)}")
    
    # Add self-vote
    votes += 1
    
    total_nodes = len(peer_stub_map) + 1  # +1 for self


    if reachable_peers == 0:
        majority = 1
    else:
        # Check if we have majority
        majority = (total_nodes // 2) + 1
    
    if votes >= majority:
        logger.info(f"Won election for term {term} with {votes}/{total_nodes} votes")
        
        # Update our own leader status
        if blockchain_servicer:
            blockchain_servicer.current_leader_address = server_address
            blockchain_servicer.is_leader = True
            logger.info(f"Setting self as leader. My address: {server_address}")
        
        # Send NotifyLeadership to all peers
        leadership_request = block_chain_pb2.NotifyLeadershipRequest(
            address=server_address
        )
        
        for peer_address, stub in peer_stub_map.items():
            try:
                logger.info(f"Notifying {peer_address} of leadership")
                response = stub.NotifyLeadership(
                    leadership_request, 
                    timeout=5  # 5 second timeout
                )
                logger.info(f"NotifyLeadership to {peer_address} response: {response.status}")
                
            except grpc.RpcError as e:
                logger.error(f"Error notifying leadership to {peer_address}: {e.code()}: {e.details()}")
            except Exception as e:
                logger.error(f"Unexpected error notifying leadership to {peer_address}: {str(e)}")
        
        # Start block proposal thread now that we're the leader
        logger.info("Starting automatic block proposal thread as the new leader")
        block_proposal_thread = threading.Thread(
            target=create_and_propose_blocks,
            args=(server_address, peer_stub_map, blockchain, mempool, blockchain_servicer),
            daemon=True
        )
        block_proposal_thread.start()
        
        return True
    else:
        logger.info(f"Lost election for term {term} with {votes}/{total_nodes} votes")
        return False

def sync_missing_blocks(server_address, peer_stub_map, blockchain):
    """
    Synchronize missing blocks from peers.
    
    This function is called when a node starts up or detects it's missing blocks.
    It queries peers for their latest block ID and syncs all missing blocks.
    
    
    """
    logger.info("Starting block synchronization process")
    
    # Get our latest block ID
    latest_block = blockchain.get_latest_block()
    our_latest_block_id = latest_block.id if latest_block else -1
    logger.info(f"Our latest block ID: {our_latest_block_id}")
    
    # Keep track of peers' latest block IDs
    peer_latest_blocks = {}
    highest_block_id = our_latest_block_id
    sync_source = None
    
    # Query peers for their latest block IDs through heartbeat
    for peer_address, stub in peer_stub_map.items():
        try:
            # Create a heartbeat message to exchange blockchain info
            heartbeat_request = block_chain_pb2.HeartbeatRequest(
                from_address=server_address,
                current_leader_address="",  # Not setting leader
                latest_block_id=our_latest_block_id,
                mem_pool_size=0
            )
            
            # Send the request
            response = stub.SendHeartbeat(heartbeat_request, timeout=5)
            
            # Get peer's latest block ID using the GetBlock method with a high ID
            # This will trigger an error that contains the peer's highest block ID
            try:
                # Try to get a block with a very high ID to see what error we get
                test_response = stub.GetBlock(block_chain_pb2.GetBlockRequest(id=1000000))
                # If we get here, the peer actually has this block (unlikely)
                peer_block_id = 1000000
                peer_latest_blocks[peer_address] = peer_block_id
                logger.info(f"Peer {peer_address} has very high block ID: {peer_block_id}")
                
                # Update the highest block ID seen
                if peer_block_id > highest_block_id:
                    highest_block_id = peer_block_id
                    sync_source = peer_address
            except grpc.RpcError as e:
                # This will fail, and now we can parse the error to find the latest block ID
                error_details = e.details() if hasattr(e, 'details') else str(e)
                # Try multiple patterns to extract the highest block ID from error messages
                patterns = [
                    r"highest block ID is (\d+)",
                    r"Block not found\.\s+The highest block ID is (\d+)",
                    r"latest block.*?(\d+)",
                    r"highest.*?block.*?(\d+)"  # Most general pattern, try last
                ]
                
                peer_block_id = None
                for pattern in patterns:
                    match = re.search(pattern, error_details, re.IGNORECASE)
                    if match:
                        try:
                            peer_block_id = int(match.group(1))
                            break
                        except (ValueError, IndexError):
                            continue
                            
                if peer_block_id is not None:
                    peer_latest_blocks[peer_address] = peer_block_id
                    logger.info(f"Peer {peer_address} has latest block ID: {peer_block_id}")
                    
                    # Update the highest block ID seen
                    if peer_block_id > highest_block_id:
                        highest_block_id = peer_block_id
                        sync_source = peer_address
            
        except Exception as e:
            logger.error(f"Error querying peer {peer_address} for latest block: {str(e)}")
    
    # If no peers or all peers have same or lower block ID, no sync needed
    if not sync_source:
        logger.info("No synchronization needed, our chain is up to date")
        return
    
    logger.info(f"Syncing {highest_block_id - our_latest_block_id} blocks from peer {sync_source}")
    
    # Sync blocks from the peer with the highest block ID
    stub = peer_stub_map[sync_source]
    for block_id in range(our_latest_block_id + 1, highest_block_id + 1):
        try:
            # Get the block from the peer
            response = stub.GetBlock(block_chain_pb2.GetBlockRequest(id=block_id))
            
            if response.status == "success" and response.block:
                # Add the block to our chain
                if blockchain.add_block(response.block):
                    logger.info(f"Successfully synced block {block_id} from peer {sync_source}")
                else:
                    logger.error(f"Failed to add block {block_id} to our chain")
                    # If we can't add a block, stop syncing to maintain chain integrity
                    break
            else:
                logger.error(f"Failed to get block {block_id} from peer {sync_source}: {response.error_message}")
                break
                
        except Exception as e:
            logger.error(f"Error syncing block {block_id} from peer {sync_source}: {str(e)}")
            break
    
    # Check if we successfully synced all blocks
    latest_block = blockchain.get_latest_block()
    new_latest_id = latest_block.id if latest_block else -1
    if new_latest_id == highest_block_id:
        logger.info(f"Successfully synchronized all missing blocks. Chain now at block {new_latest_id}")
    else:
        logger.warning(f"Partial synchronization completed. Chain now at block {new_latest_id}, target was {highest_block_id}")

def block_sync_monitor(server_address, peer_stub_map, blockchain, blockchain_servicer, interval=30):
    """
    Continuously monitor the network for missing blocks and sync them.
    
    This function runs as a background thread to ensure this node always
    stays in sync with the blockchain network.
    
    
    """
    logger.info(f"Starting block synchronization monitor thread, checking every {interval} seconds")
    
    # Keep track of heartbeat responses that include latest block IDs
    peer_block_info = {}
    
    while True:
        try:
            # Get our latest block ID
            latest_block = blockchain.get_latest_block()
            our_latest_block_id = latest_block.id if latest_block else -1
            
            # Check heartbeat data to see if any peers have newer blocks
            sync_needed = False
            for peer_address, block_id in peer_block_info.items():
                if block_id > our_latest_block_id:
                    logger.info(f"Detected peer {peer_address} has newer blocks (ID: {block_id}, ours: {our_latest_block_id})")
                    sync_needed = True
                    break
                    
            # If we've detected newer blocks, sync them
            if sync_needed:
                sync_missing_blocks(server_address, peer_stub_map, blockchain)
            
            # Wait for next check
            time.sleep(interval)
            
            # Update peer_block_info based on heartbeat data
            # This is where we'd collect the block IDs from heartbeats received
            # For efficiency, we access the shared data that the heartbeat function collects
            if hasattr(blockchain_servicer, 'peer_latest_block_ids'):
                peer_block_info = blockchain_servicer.peer_latest_block_ids.copy()
            
        except Exception as e:
            logger.error(f"Error in block sync monitor: {str(e)}")
            # Don't crash the monitor thread, just wait and retry
            time.sleep(interval)

def create_and_propose_blocks(server_address, peer_stub_map, blockchain, mempool, blockchain_servicer, min_audits=3):
    """
    Automatically create and propose blocks when there are enough audits in the mempool.
    This function runs as a background thread when the node is the leader.
 
    """
    logger.info(f"Starting automatic block proposal thread, minimum audits: {min_audits}")
    
    while True:
        try:
            # Check if we're still the leader
            if server_address != blockchain_servicer.current_leader_address:
                logger.info(f"Not the leader (current leader: {blockchain_servicer.current_leader_address}), stopping block proposal thread")
                return
            
            # Log our current status as leader and mempool status
            with mempool.lock:
                mempool_size = len(mempool.audits)
                
            logger.info(f"Leader status check - I am the leader ({server_address}). Mempool size: {mempool_size}/{min_audits} required audits")
                
            # Check if there are enough audits in the mempool
            if mempool_size >= min_audits:
                logger.info(f"CREATING BLOCK: Found {mempool_size} audits in mempool, creating a new block (minimum required: {min_audits})")
                
                # Atomically take-and-remove audits from mempool
                with mempool.lock:
                    reserved_audits = []
                    for _ in range(min_audits):
                        if not mempool.audits:
                            break
                        reserved_audits.append(mempool.audits.popleft())
                
                # Use reserved_audits to build the block
                audits = reserved_audits
                
                # Create the block
                # Get latest block for chaining
                latest_block = blockchain.get_latest_block()
                block_id = 0 if latest_block is None else latest_block.id + 1
                previous_hash = "" if latest_block is None else latest_block.hash
                
                # Build merkle root
                audit_ids = [audit.req_id for audit in audits]
                merkle_root = ""
                if audit_ids:
                    # Hash the leaves
                    leaves = [hashlib.sha256(audit_id.encode()).hexdigest() for audit_id in audit_ids]
                    
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
                            
                        # Move to the next level
                        current_level = next_level
                    
                    merkle_root = current_level[0]
                
                # Create block hash
                data = f"{block_id}{previous_hash}{merkle_root}".encode()
                block_hash = hashlib.sha256(data).hexdigest()
                
                # Create block message
                block = block_chain_pb2.Block(
                    id=block_id,
                    hash=block_hash,
                    previous_hash=previous_hash,
                    audits=audits,
                    merkle_root=merkle_root,
                )
                
                logger.info(f"Created block {block_id} with {len(audits)} audits, proposing to peers")
                
                # Propose the block to all peers and require unanimous agreement
                all_agreed = True
                peer_responses = {}
                
                for peer_address, stub in peer_stub_map.items():
                    try:
                        logger.info(f"Proposing block {block_id} to {peer_address}")
                        response = stub.ProposeBlock(block)
                        peer_responses[peer_address] = response
                        
                        if not response.vote:
                            all_agreed = False
                            logger.warning(f"Peer {peer_address} rejected block: {response.error_message}")
                            
                    except Exception as e:
                        all_agreed = False
                        logger.error(f"Error proposing block to {peer_address}: {str(e)}")
                
                # If all peers agreed, commit the block
                if all_agreed and peer_stub_map:  # Make sure we have at least one peer
                    logger.info(f"All peers agreed to block {block_id}, committing")
                    
                    # Save block locally first
                    if blockchain.add_block(block):
                        logger.info(f"Block {block_id} added to local blockchain")
                        
                        # Remove the audits from local mempool
                        audit_ids = [audit.req_id for audit in audits]
                        mempool.remove_audits(audit_ids)
                        
                        # Commit the block to all peers
                        for peer_address, stub in peer_stub_map.items():
                            try:
                                logger.info(f"Committing block {block_id} to {peer_address}")
                                response = stub.CommitBlock(block)
                                if response.status != "success":
                                    logger.warning(f"Peer {peer_address} failed to commit block: {response.error_message}")
                            except Exception as e:
                                logger.error(f"Error committing block to {peer_address}: {str(e)}")
                    else:
                        logger.error(f"Failed to add block {block_id} to local blockchain")
                else:
                    logger.warning(f"Block proposal rejected by one or more peers, not committing block {block_id}")
            
            # Sleep for a bit before checking again
            time.sleep(5)
                
        except Exception as e:
            logger.error(f"Error in block proposal loop: {str(e)}")
            # Don't crash the proposal thread, just wait and retry
            time.sleep(5)

def get_local_ip():
    """Get the local IP address of this machine in a private network."""
    try:
        # For a private network with only two computers,
        # try connecting to the peer to get the correct interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        s.connect(("0.0.0.0", 80))  
        ip = s.getsockname()[0]
        s.close()
        
        # Verify we have a proper IP for the private network
        if not ip.startswith("169.254"):
            # If the automatic detection didn't work, try to find all available IPs
            import subprocess
            import re
            
            # Get all network interfaces using ifconfig (available on macOS)
            try:
                output = subprocess.check_output(["ifconfig"], universal_newlines=True)
                # Look for 169.254.x.x addresses in the output
                # Pattern for IPv4 addresses
                pattern = r'inet\s+(\d+\.\d+\.\d+\.\d+)'
                addresses = re.findall(pattern, output)
                
                # Find the first 169.254.x.x address
                for addr in addresses:
                    if addr.startswith('169.254'):
                        ip = addr
                        break
            except Exception:
                logger.warning("Could not detect interface with ifconfig")
                
        # Fallback to hardcoded IP if we still don't have a valid one
        if not ip.startswith("169.254"):
            ip = "169.254.44.212"  # Your specific IP in the private network
            
        logger.info(f"Using private network IP address: {ip}")
        return ip
    except Exception as e:
        logger.error(f"Error getting private network IP: {str(e)}")
        # Default to your known private network IP
        logger.warning(f"Using hardcoded private network IP address: 169.254.44.212")
        return "169.254.44.212"

def serve(port, peer_addresses=None, slot_duration=10, config_file=None, disable_sync=False):
    """
    Start the server as a follower node.


    """
    # Load configuration if peer_addresses not provided
    if peer_addresses is None:
        try:
            config = load_config(config_file)
            peer_addresses = get_peer_addresses(config)
            server_config = get_server_config(config)
            max_workers = server_config.get('max_workers', 10)
            heartbeat_interval = server_config.get('heartbeat_interval', 5)
            logger.info(f"Loaded configuration: {len(peer_addresses)} peers, " 
                      f"{heartbeat_interval}s heartbeat interval, {max_workers} max workers")
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}. Using defaults.")
            peer_addresses = []
            max_workers = 10
            heartbeat_interval = 5
    else:
        # Use defaults if not loading from config
        max_workers = 10
        heartbeat_interval = 5
        
    # Create a mempool
    mempool = Mempool()
    
    # Create blockchain instance
    blockchain = Blockchain()

    # Create stubs for blockchain services and maintain a mapping of addresses to stubs
    blockchain_stubs = []
    peer_stub_map = {}
    for address in peer_addresses:
        logger.info(f"Connecting to peer at {address}")
        channel = grpc.insecure_channel(address)
        stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
        blockchain_stubs.append(stub)
        peer_stub_map[address] = stub

    # Create a server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))

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
    # Use socket.gethostname() to get the local hostname for identification
    import socket

    server_address = f"{get_local_ip()}:{port}"
    heartbeat_thread = threading.Thread(
        target=send_heartbeats, 
        args=(server_address, peer_stub_map, blockchain, mempool, blockchain_servicer, heartbeat_interval),
        daemon=True
    )
    heartbeat_thread.start()
    logger.info(f"Started heartbeat sender thread, will send heartbeats every {heartbeat_interval} seconds to {len(peer_stub_map)} peers")

    # Variable to track if block proposal thread is running
    block_proposal_thread_started = False
    
    # Initialize leadership check timer - if we don't have a leader initially, trigger election
    def check_leadership():
        nonlocal block_proposal_thread_started
        
        if not blockchain_servicer.current_leader_address:
            logger.info("No leader detected on startup, triggering election")
            if trigger_election(server_address, peer_stub_map, blockchain, mempool, 1, blockchain_servicer):
                # We won the election, set ourselves as leader
                blockchain_servicer.current_leader_address = server_address
                blockchain_servicer.is_leader = True
                logger.info(f"Election succeeded, setting self as leader: {server_address}")
                
                # Start block proposal thread
                if not block_proposal_thread_started:
                    block_proposal_thread_started = True
                    logger.info(f"Starting automatic block proposal thread as leader with {len(mempool.audits)} audits in mempool")
                    block_proposal_thread = threading.Thread(
                        target=create_and_propose_blocks,
                        args=(server_address, peer_stub_map, blockchain, mempool, blockchain_servicer),
                        daemon=True
                    )
                    block_proposal_thread.start()
        
        elif server_address == blockchain_servicer.current_leader_address:
            # We're already the leader, start block proposal if not already
            if not block_proposal_thread_started:
                block_proposal_thread_started = True
                logger.info(f"We are the leader, starting automatic block proposal thread with {len(mempool.audits)} audits in mempool")
                block_proposal_thread = threading.Thread(
                    target=create_and_propose_blocks,
                    args=(server_address, peer_stub_map, blockchain, mempool, blockchain_servicer),
                    daemon=True
                )
                block_proposal_thread.start()
    
    # Start leadership check after a short delay to let connections establish
    leadership_timer = threading.Timer(30.0, check_leadership)
    leadership_timer.daemon = True
    leadership_timer.start()
    
    # Also create a periodic check for leadership status 
    def periodic_leadership_check():
        nonlocal block_proposal_thread_started
        
        while True:
            try:
                time.sleep(15)  # Check every 15 seconds
                
                # If we are the leader but proposal thread is not running, start it
                if server_address == blockchain_servicer.current_leader_address and not block_proposal_thread_started:
                    block_proposal_thread_started = True
                    logger.info(f"Periodic check: We are the leader, starting automatic block proposal thread with {len(mempool.audits)} audits in mempool")
                    block_proposal_thread = threading.Thread(
                        target=create_and_propose_blocks,
                        args=(server_address, peer_stub_map, blockchain, mempool, blockchain_servicer),
                        daemon=True
                    )
                    block_proposal_thread.start()
                
                # If proposal thread is marked as running but we're not leader anymore, reset flag
                if server_address != blockchain_servicer.current_leader_address and block_proposal_thread_started:
                    logger.info("No longer the leader, resetting block proposal thread status")
                    block_proposal_thread_started = False
                    
            except Exception as e:
                logger.error(f"Error in periodic leadership check: {str(e)}")
    
    # Start periodic leadership check
    periodic_check_thread = threading.Thread(
        target=periodic_leadership_check,
        daemon=True
    )
    periodic_check_thread.start()
    
    # Start block synchronization process (if not disabled)
    if not disable_sync:
        logger.info("Performing initial block synchronization...")
        sync_missing_blocks(server_address, peer_stub_map, blockchain)
        
        # Start block synchronization monitor thread
        block_sync_thread = threading.Thread(
            target=block_sync_monitor, 
            args=(server_address, peer_stub_map, blockchain, blockchain_servicer),
            daemon=True
        )
        block_sync_thread.start()
        logger.info("Started block synchronization monitor thread")
    else:
        logger.info("Block synchronization is disabled (--disable-sync flag set)")

    try:
        while True:
            time.sleep(86400)  # Sleep for a day
    except KeyboardInterrupt:
        server.stop(0)
        logger.info("Server stopped")


def main():
    """Main function for the server."""
    parser = argparse.ArgumentParser(description="File Audit Server")
    parser.add_argument("--port", type=int, default=50051, help="Port to listen on")
    parser.add_argument("--peers", nargs="*", default=None, help="Peer addresses (overrides config file)")
    parser.add_argument("--config", type=str, default=None, 
                       help="Path to configuration file (default: config.yaml in project root)")
    parser.add_argument("--disable-sync", action="store_true", 
                       help="Disable automatic block synchronization")

    args = parser.parse_args()

    serve(args.port, args.peers, config_file=args.config, disable_sync=args.disable_sync)


if __name__ == "__main__":
    main()
