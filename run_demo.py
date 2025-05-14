import os
import sys
import time
import threading
import argparse
import importlib.util
import socket
import logging

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

# Import config utilities
from src.utils.config import load_config, get_peer_addresses

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


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


def generate_proto():
    """Generate Python code from proto files."""
    print("Generating Python code from proto files...")
    # Import the generate_proto module
    spec = importlib.util.spec_from_file_location("generate_proto", "generate_proto.py")
    generate_proto_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generate_proto_module)

    # Call the generate_proto function
    generate_proto_module.generate_proto()
    print("Done generating Python code.")


def start_server(port, peers=None, config_file=None, use_heartbeat=True):
    """
    Start a server in a separate thread.
    
    Args:
        port: Port to listen on
        peers: List of peer addresses (if None, load from config)
        config_file: Path to config file (if None, use default)
        use_heartbeat: If True, use server_with_heartbeat.py instead of server.py
    """
    if use_heartbeat:
        # Use the enhanced server with heartbeat functionality
        from src.server.server_with_heartbeat import serve
        logger.info("Using server with heartbeat functionality")
    else:
        # Use the original server implementation
        from src.server.server import serve
        logger.info("Using basic server implementation")

    logger.info(f"Starting server on port {port}...")
    if peers:
        logger.info(f"Using provided peers: {peers}")

    # Create a thread to run the server
    server_thread = threading.Thread(
        target=serve,
        args=(port, peers),
        kwargs={'config_file': config_file},
        daemon=True,  # Make the thread a daemon so it exits when the main thread exits
    )

    # Start the server thread
    server_thread.start()

    # Wait for the server to start
    time.sleep(2)

    return server_thread


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Run a demo of the file audit system")
    parser.add_argument("--file", default="run_demo.py", help="File to audit")
    parser.add_argument("--server-port", type=int, default=50051, help="Server port")
    parser.add_argument("--local-only", action="store_true", 
                       help="Use localhost instead of physical network addresses")
    parser.add_argument("--num-audits", type=int, default=1,
                       help="Number of audits to submit")
    parser.add_argument("--client-delay", type=int, default=2,
                       help="Seconds between client audit submissions")
    parser.add_argument("--config", type=str, default=None,
                       help="Path to configuration file")
    parser.add_argument("--no-heartbeat", action="store_true",
                       help="Use basic server implementation without heartbeat")

    args = parser.parse_args()

    # Generate Python code from proto files
    generate_proto()
    
    # Get local IP address
    local_ip = get_local_ip()
    logger.info(f"Local IP address: {local_ip}")
    
    try:
        # Load peer addresses from configuration
        config = load_config(args.config)
        all_peer_addresses = get_peer_addresses(config)
        logger.info(f"Loaded {len(all_peer_addresses)} peer addresses from configuration")
        
        # Filter out our own address
        peers = []
        for addr in all_peer_addresses:
            ip = addr.split(":")[0]
            if ip != local_ip:  # Don't add ourselves as a peer
                peers.append(addr)
                
        logger.info(f"Using {len(peers)} peers after filtering out self")
        
        # this is to send audit request to the server - use first peer by default
        # This should be replaced with proper peer selection/leader election logic
        server_address = peers[0] if peers else None
        
    except Exception as e:
        logger.error(f"Error loading peer configuration: {str(e)}")
        peers = []
        server_address = None
        
    # Start the server
    server_thread = start_server(
        args.server_port, 
        peers, 
        config_file=args.config,
        use_heartbeat=not args.no_heartbeat
    )

    try:

        # Keep the servers running
        print("\nServer is running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping server...")
        print("Done.")


if __name__ == "__main__":
    main()
