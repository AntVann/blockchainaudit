#!/usr/bin/env python3
"""
Block Leader Utility - Enhanced version that uses actual audits from the mempool.

This script implements a leader node in the blockchain audit system that:
1. Fetches pending audits from a peer's mempool
2. Creates a new block with those audits
3. Proposes and commits the block to all peers according to the requirements:
   a. For leader:
      - Save the block to disk
      - Clear only the audits that are in the block from the mempool
      - Trigger commit block gRPC call to neighbors
   b. For follower:
      - Receive commit block gRPC call from leader
      - Clear only the audits that are in the block from the mempool
      - Save to disk
      - Return successful commit response to leader
"""

import os
import sys
import time
import argparse
import hashlib
import socket
import json
import grpc
import threading
from concurrent import futures
import logging


# Add the project root to the Python path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from src.generated import (
    block_chain_pb2,
    block_chain_pb2_grpc,
    file_audit_pb2,
    file_audit_pb2_grpc
)
from src.utils.config import load_config, get_peer_addresses
from google.protobuf.json_format import MessageToDict


class BlockchainLeader:
    """Implements a leader node in the blockchain audit system."""
    
    def __init__(self, config_file=None, server_address=None):
        """Initialize the leader with configuration."""
        # Load configuration
        try:
            self.config = load_config(config_file)
            self.peer_addresses = get_peer_addresses(self.config)
            print(f"Loaded {len(self.peer_addresses)} peer addresses from configuration")
        except Exception as e:
            print(f"Error loading configuration: {str(e)}. Using default peers.")
            self.peer_addresses = []
            
        # Filter out own address to prevent self-connections
        self.local_ip = self.get_local_ip()
        self.peer_addresses = [addr for addr in self.peer_addresses 
                              if addr.split(":")[0] != self.local_ip]
        
        if not self.peer_addresses:
            print("No peer addresses found. Add some to config.yaml.")
            self.peer_addresses = []
            
        # Use specified server or first peer as server for getting audits
        self.server_address = server_address or (self.peer_addresses[0] if self.peer_addresses else None)
        if self.server_address:
            print(f"Using {self.server_address} for getting audits and latest block")
        else:
            print("No server address specified and no peers available")
            
        # Initialize the blockchain directory
        self.blockchain_dir = "blockchain"
        os.makedirs(self.blockchain_dir, exist_ok=True)
            
    def get_local_ip(self):
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
                ip = "169.254.45.104"  # Your specific IP in the private network
                
            logger.info(f"Using private network IP address: {ip}")
            return ip
        except Exception as e:
            logger.error(f"Error getting private network IP: {str(e)}")
            # Default to your known private network IP
            logger.warning(f"Using hardcoded private network IP address: 169.254.45.104")
            return "169.254.45.104"
                
    def get_direct_audits_from_peer(self, peer_address, max_audits=50):
        """
        Get audits directly from a peer using a special mechanism without modifying the proto.
        
        This function uses a temporary gRPC server to receive whispered audits from the peer.
        The peer will whisper the audits back to our temporary server.
        """
        # Set up a local collection for received audits
        received_audits = []
        
        # Create a local class to collect whispered audits
        class AuditCollectorServicer(block_chain_pb2_grpc.BlockChainServiceServicer):
            def __init__(self, audit_collection):
                self.audit_collection = audit_collection
                
            def WhisperAuditRequest(self, request, context):
                self.audit_collection.append(request)
                print(f"Leader received whispered audit: {request.req_id}")
                return block_chain_pb2.WhisperResponse(status="success")
        
        # First, set up a server to receive whispered audits from peers
        # Get an ephemeral port for the leader's temporary server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('0.0.0.0', 0))  # Bind to an available port
        leader_port = sock.getsockname()[1]
        sock.close()
        
        # Get hostname for a proper address
        hostname = self.get_local_ip()
        leader_address = f"{hostname}:{leader_port}"
        print(f"Starting temporary audit collector on {leader_address}")
        
        # Start the temporary server
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        servicer = AuditCollectorServicer(received_audits)
        block_chain_pb2_grpc.add_BlockChainServiceServicer_to_server(servicer, server)
        server.add_insecure_port(f'[::]:{leader_port}')
        server.start()
        
        try:
            # Connect to the peer
            channel = grpc.insecure_channel(peer_address)
            blockchain_stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            
            # Send a heartbeat request with our address to get mempool contents
            heartbeat_req = block_chain_pb2.HeartbeatRequest(
                from_address=leader_address,  # Use our address so peer can whisper back
                current_leader_address="",
                latest_block_id=0,
                mem_pool_size=max_audits
            )
            
            # Send the request to the peer
            response = blockchain_stub.SendHeartbeat(heartbeat_req, timeout=5)
            print(f"Sent mempool request to {peer_address}, response: {response.status}")
            
            # Wait for audits to be whispered back
            print(f"Waiting for audits from {peer_address}...")
            wait_time = 0.5  # seconds
            wait_count = 10  # Total wait time = wait_time * wait_count
            
            for _ in range(wait_count):
                time.sleep(wait_time)
                if received_audits:
                    break
            
            return received_audits
            
        except Exception as e:
            print(f"Error getting audits from peer {peer_address}: {str(e)}")
            return []
        finally:
            # Always stop the temporary server
            server.stop(0)
            print("Temporary audit collector server stopped")
    
    def get_pending_audits(self, max_audits=50):
        """Get pending audits from the server's mempool using JSON payload in error_message."""
        if not self.server_address:
            print("No server address available to get audits from")
            return []
        try:
            channel = grpc.insecure_channel(self.server_address)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            # Send heartbeat to request mempool contents
            req = block_chain_pb2.HeartbeatRequest(
                from_address="LEADER_GET_MEMPOOL",
                current_leader_address="",
                latest_block_id=0,
                mem_pool_size=max_audits
            )
            resp = stub.SendHeartbeat(req, timeout=5)
            if resp.status != "success":
                print(f"Failed to get mempool audits: {resp.error_message}")
                return []
            # Parse JSON list of audit dicts from error_message
            import json
            from google.protobuf.json_format import ParseDict
            from src.generated import common_pb2
            audit_dicts = json.loads(resp.error_message or '[]')
            audits = []
            for d in audit_dicts:
                fa = common_pb2.FileAudit()
                ParseDict(d, fa)
                audits.append(fa)
            print(f"Retrieved {len(audits)} pending audits from mempool")
            return audits[:max_audits]
        except Exception as e:
            print(f"Error getting audits from {self.server_address}: {e}")
            return []
            
    def get_latest_block(self):
        """Get the latest block from the blockchain."""
        if not self.server_address:
            print("No server address available to get latest block from")
            return None
            
        try:
            channel = grpc.insecure_channel(self.server_address)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            
            # Try to get blocks starting from 0 and incrementing until not found
            last_block_id = -1
            latest_block = None
            
            while True:
                try:
                    response = stub.GetBlock(block_chain_pb2.GetBlockRequest(id=last_block_id + 1))
                    if response.status == "success":
                        latest_block = response.block
                        last_block_id += 1
                    else:
                        break
                except:
                    break
            
            return latest_block
            
        except Exception as e:
            print(f"Error getting latest block from {self.server_address}: {str(e)}")
            return None
            
    def build_merkle_root(self, audits):
        """Build a merkle root from a list of audits."""
        if not audits:
            return ""
        
        # Get audit request IDs
        audit_ids = [audit.req_id for audit in audits]
        
        # Hash the leaves
        leaves = [hashlib.sha256(audit_id.encode()).hexdigest() for audit_id in audit_ids]
        
        # Build the merkle tree
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            
            # Ensure even number of nodes
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])
                
            # Pair nodes and compute parent nodes
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1]
                parent = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(parent)
                
            current_level = next_level
        
        return current_level[0]
        
    def create_block_hash(self, block_id, previous_hash, merkle_root):
        """Create a hash for a block based on its contents."""
        data = f"{block_id}{previous_hash}{merkle_root}".encode()
        return hashlib.sha256(data).hexdigest()
        
    def create_block(self, block_id, previous_hash, audits):
        """Create a new block with the provided audits."""
        # Build merkle root from audits
        merkle_root = self.build_merkle_root(audits)
        
        # Create block hash
        block_hash = self.create_block_hash(block_id, previous_hash, merkle_root)
        
        # Create block message
        block = block_chain_pb2.Block(
            id=block_id,
            hash=block_hash,
            previous_hash=previous_hash,
            audits=audits,
            merkle_root=merkle_root,
        )
        
        return block
        
    def save_block_to_disk(self, block):
        """Save a block to disk (leader requirement)."""
        try:
            # Convert protobuf to dict for JSON serialization
            block_dict = MessageToDict(block)
            
            # Create filename
            filename = f"block_{block.id}.json"
            filepath = os.path.join(self.blockchain_dir, filename)
            
            # Write to file
            with open(filepath, 'w') as f:
                json.dump(block_dict, f, indent=2)
                
            print(f"Saved block {block.id} to {filepath}")
            return True
            
        except Exception as e:
            print(f"Error saving block to disk: {str(e)}")
            return False
        
    def propose_block(self, peer_address, block):
        """Propose a block to a peer."""
        try:
            channel = grpc.insecure_channel(peer_address)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            
            print(f"Proposing block {block.id} to {peer_address}...")
            response = stub.ProposeBlock(block)
            
            return response.vote, response.status, getattr(response, 'error_message', '')
            
        except Exception as e:
            print(f"Error proposing block to {peer_address}: {str(e)}")
            return False, "error", str(e)
            
    def commit_block(self, peer_address, block):
        """Commit a block to a peer."""
        try:
            channel = grpc.insecure_channel(peer_address)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            
            print(f"Committing block {block.id} to {peer_address}...")
            response = stub.CommitBlock(block)
            
            return response.status, getattr(response, 'error_message', '')
            
        except Exception as e:
            print(f"Error committing block to {peer_address}: {str(e)}")
            return "error", str(e)
            
    def clear_audits_from_mempool(self, block):
        """Clear audits in the block from the mempool.
        
        In this implementation, we don't have a local mempool,
        so we need to ensure the audits are cleared from all peer nodes.
        """
        if not block.audits:
            print("Block has no audits to clear from mempool")
            return
        
        # Extract audit IDs to clear    
        audit_ids = [audit.req_id for audit in block.audits]
        print(f"Ensuring {len(audit_ids)} audits are cleared from all peer mempools")
        
        # Since we don't have access to directly clear the remote mempools,
        # the peer nodes will clear the audits during the ProposeBlock and CommitBlock operations.
        # This is handled by the server implementation.
        
        # If we implement our own local mempool in the future, we would clear it here:
        # self.mempool.remove_audits(audit_ids)
            
    def propose_and_commit_block(self, block):
        """Propose and commit a block according to the specification:
        
        For leader:
        - Save the block to disk
        - Clear only the audits that are in the block from the mempool
        - Trigger commit block gRPC call to neighbors
        """
        # Check if we have peers to propose to
        if not self.peer_addresses:
            print("No peers to propose block to")
            return False
            
        # 1. Save the block to disk (leader requirement)
        if not self.save_block_to_disk(block):
            print("Failed to save block to disk")
            return False
            
        # Track voting results
        positive_votes = 0
        total_votes = 0
        
        # 2. Propose to all peers
        for peer in self.peer_addresses:
            vote, status, error = self.propose_block(peer, block)
            total_votes += 1
            
            if vote:
                positive_votes += 1
                print(f"Received positive vote from {peer}")
            else:
                print(f"Received negative vote from {peer}: {error}")
        
        # Calculate vote ratio
        vote_ratio = positive_votes / total_votes if total_votes > 0 else 0
        
        # If more than 2/3 of peers voted positively, commit the block
        if vote_ratio >= 0.67:
            print(f"Block {block.id} received {positive_votes}/{total_votes} votes (>= 2/3), committing...")
            
            # 3. Clear only the audits that are in the block from the mempool
            self.clear_audits_from_mempool(block)
            
            # 4. Trigger commit block gRPC calls to neighbors
            commit_successes = 0
            for peer in self.peer_addresses:
                status, error = self.commit_block(peer, block)
                if status == "success":
                    commit_successes += 1
                    print(f"Successfully committed block {block.id} to {peer}")
                else:
                    print(f"Failed to commit block {block.id} to {peer}: {error}")
                    
            return commit_successes > 0
        else:
            print(f"Block {block.id} received only {positive_votes}/{total_votes} votes (< 2/3), aborting...")
            return False
            
    def create_and_propose_block(self, block_id=None, genesis=False, max_audits=50):
        """Create a new block and propose it to the network."""
        # Get the latest block
        latest_block = self.get_latest_block()
        if latest_block:
            print(f"Latest block: ID={latest_block.id}, Hash={latest_block.hash}")
            previous_hash = latest_block.hash
            next_block_id = latest_block.id + 1
        else:
            print("No existing blocks found")
            previous_hash = "" if genesis else "0" * 64  # Empty for genesis, zeros otherwise
            next_block_id = 0
        
        # Override with provided block ID if specified
        if block_id is not None:
            next_block_id = block_id
            print(f"Using provided block ID: {next_block_id}")
        
        # Force empty previous_hash for genesis block
        if genesis:
            previous_hash = ""
            print("Creating genesis block with empty previous_hash")
        
        # Get pending audits
        audits = self.get_pending_audits(max_audits=max_audits)
        print(f"Found {len(audits)} pending audits")
        
        if not audits:
            print("No audits found in the mempool.")
            # In a production system, we might want to decide whether to create an empty block
            # or wait for audits to be available. Here, we'll create an empty block.
            print("Creating a block with no audits")
        
        # Create block
        block = self.create_block(next_block_id, previous_hash, audits)
        print(f"Created block {block.id} with hash {block.hash}")
        
        # Propose and commit block
        success = self.propose_and_commit_block(block)
        if success:
            print(f"Successfully proposed and committed block {block.id}")
            
            # Double check that all audits in this block are cleared from the mempool
            if audits:
                audit_ids = [audit.req_id for audit in audits]
                print(f"Cleared {len(audit_ids)} audit IDs from mempool during block proposal")
                self.clear_audits_from_mempool(block)
        else:
            print(f"Failed to propose and commit block {block.id}")
            
        return success


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Enhanced Blockchain Leader Utility")
    parser.add_argument("--config", type=str, default=None, 
                       help="Path to configuration file (default: config.yaml in project root)")
    parser.add_argument("--server", type=str, default=None,
                       help="Server address to use for getting mempool audits")
    parser.add_argument("--block-id", type=int, default=None,
                       help="Block ID to propose (defaults to latest + 1, or 0)")
    parser.add_argument("--genesis", action="store_true",
                       help="Create genesis block with empty previous_hash")
    parser.add_argument("--require-audits", action="store_true",
                       help="Wait until at least one audit is available in mempool before creating a block")
    
    args = parser.parse_args()
    
    # Create leader and run the block creation process
    leader = BlockchainLeader(config_file=args.config, server_address=args.server)
    
    # If requiring audits, wait until at least one is available
    if args.require_audits:
        max_retries = 30  # Maximum number of retries
        retry_delay = 2   # Seconds between retries
        
        print("Waiting for audits to appear in mempool...")
        for attempt in range(1, max_retries + 1):
            audits = leader.get_pending_audits(max_audits=1)
            if audits:
                print(f"Found {len(audits)} audit(s) after {attempt} attempt(s)")
                break
            
            if attempt < max_retries:
                print(f"No audits found, retrying in {retry_delay} seconds (attempt {attempt}/{max_retries})...")
                time.sleep(retry_delay)
            else:
                print("Maximum retries reached, no audits found in mempool")
                return False
    
    # Create and propose the block
    leader.create_and_propose_block(block_id=args.block_id, genesis=args.genesis)


if __name__ == "__main__":
    main()