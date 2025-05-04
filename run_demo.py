import os
import sys
import time
import threading
import argparse
import importlib.util

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))


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


def start_server(port, peers):
    """Start a server in a separate thread."""
    from src.server.server import serve

    print(f"Starting server on port {port}...")

    # Create a thread to run the server
    server_thread = threading.Thread(
        target=serve,
        args=(port, peers),
        daemon=True,  # Make the thread a daemon so it exits when the main thread exits
    )

    # Start the server thread
    server_thread.start()

    # Wait for the server to start
    time.sleep(2)

    return server_thread


def run_client(server_address, file_path):
    """Run a client."""
    from src.client.client import FileAuditClient

    print(f"Running client to submit audit for {file_path}...")

    # Create a key directory if it doesn't exist
    os.makedirs("keys", exist_ok=True)

    # Generate keys if they don't exist
    private_key_path = "keys/private_key.pem"
    public_key_path = "keys/public_key.pem"

    # Create a client
    client = FileAuditClient(server_address, private_key_path, public_key_path)

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

    # Create and submit audit
    file_audit = client.create_file_audit(file_path, user_id, user_name, "READ")

    print(f"Submitting audit for {file_path} with access type READ")
    response = client.submit_audit(file_audit)

    if response:
        print(f"Audit submitted successfully: {response.status}")
        if response.blockchain_tx_hash:
            print(f"Blockchain transaction hash: {response.blockchain_tx_hash}")

    # Close client
    client.close()


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Run a demo of the file audit system")
    parser.add_argument("--file", default="run_demo.py", help="File to audit")
    parser.add_argument("--server-port", type=int, default=50051, help="Server port")
    parser.add_argument(
        "--peer-ports", type=int, nargs="*", default=[], help="Peer ports"
    )

    args = parser.parse_args()

    # Generate Python code from proto files
    generate_proto()

    # Start servers
    server_threads = []

    # Start the main server
    server_address = f"localhost:{args.server_port}"
    peers = [f"localhost:{port}" for port in args.peer_ports]
    main_server = start_server(args.server_port, peers)
    server_threads.append(main_server)

    # Start peer servers
    for port in args.peer_ports:
        # Each peer connects to all other peers
        peer_peers = [
            f"localhost:{p}" for p in [args.server_port] + args.peer_ports if p != port
        ]
        peer_server = start_server(port, peer_peers)
        server_threads.append(peer_server)

    try:
        # Run the client
        run_client(server_address, args.file)

        # Keep the servers running
        print("\nServers are running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping servers...")
        print("Done.")


if __name__ == "__main__":
    main()
