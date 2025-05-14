#!/usr/bin/env python3
"""
Block Leader Utility - Propose and commit blocks to the blockchain audit system.

This script allows you to act as a leader node in the blockchain audit system.
It fetches pending audits from the mempool, creates blocks, and proposes them
to other nodes in the network.
"""

import os
import sys
import time
import argparse
import hashlib
import socket
import json
import grpc

# Add the project root to the Python path
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from src.generated import (
    block_chain_pb2,
    block_chain_pb2_grpc,
    file_audit_pb2,
    file_audit_pb2_grpc
)
from src.utils.config import load_config, get_peer_addresses


def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        # Connect to a public IP address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("0.0.0.0", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def create_block_hash(block_id, previous_hash, merkle_root):
    """Create a hash for a block based on its contents."""
    data = f"{block_id}{previous_hash}{merkle_root}".encode()
    return hashlib.sha256(data).hexdigest()


def build_merkle_root(audits):
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


def get_pending_audits(server_address, max_audits=50):
    """Get pending audits from a server's mempool.
    
    This function sends a SubmitAudit request with a special audit ID that
    the server recognizes as a request to return pending audits.
    """
    try:
        # Since we don't have a direct RPC for getting mempool contents,
        # we'll create a custom endpoint in our server to fetch pending audits
        channel = grpc.insecure_channel(server_address)
        stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
        
        # Create a special audit request to get mempool contents
        print(f"Fetching pending audits from {server_address}...")
        
        # Send a special heartbeat request that we'll use to trigger sending back
        # the mempool contents through a custom field
        heartbeat_req = block_chain_pb2.HeartbeatRequest(
            from_address="LEADER_GET_MEMPOOL",  # Special marker for the server
            current_leader_address="",
            latest_block_id=0,
            mem_pool_size=max_audits  # We'll use this to indicate how many audits we want
        )
        
        response = stub.SendHeartbeat(heartbeat_req, timeout=5)
        
        # In a real implementation, you would process the response here
        # For now, let's check if we're still using dummy audits
        
        # We'll add code below to try and submit test audits and then retrieve them
        # For demonstration purposes, we'll submit a test audit and then retrieve it
        file_audit_stub = file_audit_pb2_grpc.FileAuditServiceStub(channel)
        
        # Submit a test audit
        test_audit_id = f"leader_audit_{int(time.time())}"
        audit = file_audit_pb2.FileAudit()
        audit.req_id = test_audit_id
        audit.file_info.file_id = "test_file_id"
        audit.file_info.file_name = "test_file.txt"
        audit.user_info.user_id = "test_user_id"
        audit.user_info.user_name = "Test User"
        audit.access_type = file_audit_pb2.AccessType.READ
        audit.timestamp = int(time.time())
        
        # For now, since we don't have signatures set up properly, we'll use the existing dummy audits
        # In a production environment, we would properly sign the audits
        
        # Return the test audit - in a full implementation, we would retrieve real
        # audits from the mempool after setting up a proper RPC method
        # TODO: Implement proper mempool audit retrieval
        print(f"[WARNING] Using test audit with ID {test_audit_id} - implement proper mempool retrieval")
        
        # Add a small delay to ensure audit is in mempool before we use it
        time.sleep(1)
        
        # Try to submit the audit to ensure it's in the mempool  
        try:
            submit_response = file_audit_stub.SubmitAudit(audit)
            print(f"Submitted test audit {audit.req_id}, status: {submit_response.status}")
        except Exception as e:
            print(f"Error submitting test audit: {e}")
        
        return [audit]
        
    except Exception as e:
        print(f"Error getting audits from {server_address}: {str(e)}")
        return []


def create_block(block_id, previous_hash, audits):
    """Create a new block with the provided audits."""
    # Build merkle root from audits
    merkle_root = build_merkle_root(audits)
    
    # Create block hash
    block_hash = create_block_hash(block_id, previous_hash, merkle_root)
    
    # Create block message
    block = block_chain_pb2.Block(
        id=block_id,
        hash=block_hash,
        previous_hash=previous_hash,
        audits=audits,
        merkle_root=merkle_root
    )
    
    return block


def get_latest_block(server_address):
    """Get the latest block from a server."""
    try:
        channel = grpc.insecure_channel(server_address)
        stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
        
        # We'll try to get the latest block by assuming it's block ID 0,
        # and incrementing until we get a "not found" response
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
        print(f"Error getting latest block from {server_address}: {str(e)}")
        return None


def propose_block(server_address, block):
    """Propose a block to a server."""
    try:
        channel = grpc.insecure_channel(server_address)
        stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
        
        print(f"Proposing block {block.id} to {server_address}...")
        response = stub.ProposeBlock(block)
        
        return response.vote, response.status, getattr(response, 'error_message', '')
        
    except Exception as e:
        print(f"Error proposing block to {server_address}: {str(e)}")
        return False, "error", str(e)


def commit_block(server_address, block):
    """Commit a block to a server."""
    try:
        channel = grpc.insecure_channel(server_address)
        stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
        
        print(f"Committing block {block.id} to {server_address}...")
        response = stub.CommitBlock(block)
        
        return response.status, getattr(response, 'error_message', '')
        
    except Exception as e:
        print(f"Error committing block to {server_address}: {str(e)}")
        return "error", str(e)


def propose_and_commit(peers, block):
    """Propose a block to all peers and then commit it if enough votes."""
    # Track votes
    positive_votes = 0
    total_votes = 0
    
    # Propose to all peers
    for peer in peers:
        vote, status, error = propose_block(peer, block)
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
        
        # Commit to all peers
        for peer in peers:
            status, error = commit_block(peer, block)
            if status == "success":
                print(f"Successfully committed block {block.id} to {peer}")
            else:
                print(f"Failed to commit block {block.id} to {peer}: {error}")
                
        return True
    else:
        print(f"Block {block.id} received only {positive_votes}/{total_votes} votes (< 2/3), aborting...")
        return False


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Blockchain Leader Utility")
    parser.add_argument("--config", type=str, default=None, 
                       help="Path to configuration file (default: config.yaml in project root)")
    parser.add_argument("--server", type=str, default=None,
                       help="Server address to use for getting mempool audits")
    parser.add_argument("--block-id", type=int, default=None,
                       help="Block ID to propose (defaults to latest + 1, or 0)")
    parser.add_argument("--genesis", action="store_true",
                       help="Create genesis block with empty previous_hash")
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        config = load_config(args.config)
        peer_addresses = get_peer_addresses(config)
        print(f"Loaded {len(peer_addresses)} peer addresses from configuration")
    except Exception as e:
        print(f"Error loading configuration: {str(e)}. Using default peers.")
        peer_addresses = []
    
    # Filter out own address
    local_ip = get_local_ip()
    peer_addresses = [addr for addr in peer_addresses if addr.split(":")[0] != local_ip]
    
    if not peer_addresses:
        print("No peer addresses found. Add some to config.yaml or provide --peers.")
        return
    
    # Use the first peer as server for getting audits if not specified
    server_address = args.server or peer_addresses[0]
    print(f"Using {server_address} for getting audits and latest block")
    
    # Get the latest block
    latest_block = get_latest_block(server_address)
    if latest_block:
        print(f"Latest block: ID={latest_block.id}, Hash={latest_block.hash}")
        previous_hash = latest_block.hash
        next_block_id = latest_block.id + 1
    else:
        print("No existing blocks found")
        previous_hash = "" if args.genesis else "0" * 64  # Empty for genesis, zeros otherwise
        next_block_id = 0
    
    # Override with command-line argument if provided
    if args.block_id is not None:
        next_block_id = args.block_id
        print(f"Using provided block ID: {next_block_id}")
    
    # Force empty previous_hash for genesis block
    if args.genesis:
        previous_hash = ""
        print("Creating genesis block with empty previous_hash")
    
    # Get pending audits
    audits = get_pending_audits(server_address)
    print(f"Found {len(audits)} pending audits")
    
    if not audits:
        print("No audits found, creating block with no audits")
    
    # Create block
    block = create_block(next_block_id, previous_hash, audits)
    print(f"Created block {block.id} with hash {block.hash}")
    
    # Propose and commit block
    success = propose_and_commit(peer_addresses, block)
    if success:
        print(f"Successfully proposed and committed block {block.id}")
    else:
        print(f"Failed to propose and commit block {block.id}")


if __name__ == "__main__":
    main()
