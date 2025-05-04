# Blockchain File Audit System

This project implements a private blockchain system for file auditing using gRPC. The system consists of:

1. A gRPC client that sends file audit requests with digital signatures
2. A gRPC server that validates signatures and forwards requests to other servers

## Project Structure

```
.
├── src/
│   ├── client/         # Client implementation
│   ├── server/         # Server implementation
│   ├── proto/          # Protocol buffer definitions
│   ├── utils/          # Utility functions
│   └── generated/      # Generated Python code from proto files
├── generate_proto.py   # Script to generate Python code from proto files
├── run_demo.py         # Script to run a demo of the system
└── requirements.txt    # Python dependencies
```

## Requirements

- Python 3.7+
- Dependencies listed in `requirements.txt`
- Microsoft Visual C++ 14.0 or greater (for Windows users)

## Installation

1. Clone the repository

2. For Windows users, you may need to install Microsoft C++ Build Tools:
   - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - During installation, select "Desktop development with C++"

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. If you encounter build errors with grpcio or grpcio-tools, you can try installing pre-built wheels:

```bash
pip install grpcio grpcio-tools --only-binary=:all:
```

5. Generate Python code from proto files:

```bash
python generate_proto.py
```

## Usage

### Running the Demo

The easiest way to try the system is to run the demo script:

```bash
python run_demo.py
```

This will:
1. Generate Python code from proto files
2. Start a server on port 50051
3. Create a client and send a file audit request
4. Keep the server running until you press Ctrl+C

You can also specify a file to audit and additional peer servers:

```bash
python run_demo.py --file=path/to/file --server-port=50051 --peer-ports 50052 50053
```

### Running the Server Manually

To run a server manually:

```bash
python src/server/server.py --port=50051 --peers localhost:50052 localhost:50053
```

### Running the Client Manually

To run a client manually:

```bash
python src/client/client.py --server=localhost:50051 --private-key=keys/private_key.pem --public-key=keys/public_key.pem --file=path/to/file --access-type=READ
```

## Implementation Details

### Digital Signatures

The system uses RSA keys for digital signatures:
- Private key is used to sign audit requests
- Public key is included in the audit request for verification
- Signature is created using SHA-256 hash and PKCS1v15 padding

### Blockchain Features

The server implements the following blockchain features:
- Mempool for storing unprocessed requests
- Signature validation
- "Whispering" (forwarding) requests to other servers
- Stub implementation of block proposal and voting

## Future Work

- Implement consensus algorithm for block proposer selection
- Implement node recovery mechanism
- Implement block creation and blockchain state maintenance
