import os
import sys
import subprocess
import shutil


def generate_proto():
    """Generate Python code from proto files."""
    proto_dir = os.path.join("src", "proto")
    generated_dir = os.path.join("src", "generated")

    # Create the generated directory if it doesn't exist
    os.makedirs(generated_dir, exist_ok=True)

    # Create an empty __init__.py file in the generated directory to make it a package
    with open(os.path.join(generated_dir, "__init__.py"), "w") as f:
        pass

    # Get all proto files
    proto_files = [f for f in os.listdir(proto_dir) if f.endswith(".proto")]

    # Create a temporary directory for proto compilation
    temp_dir = "temp_proto"
    os.makedirs(temp_dir, exist_ok=True)

    try:
        # Copy proto files to temp directory
        for proto_file in proto_files:
            shutil.copy(os.path.join(proto_dir, proto_file), temp_dir)

        # Generate Python code for each proto file
        for proto_file in proto_files:
            proto_path = os.path.join(temp_dir, proto_file)
            cmd = [
                sys.executable,
                "-m",
                "grpc_tools.protoc",
                f"--proto_path={temp_dir}",
                f"--python_out={generated_dir}",
                f"--grpc_python_out={generated_dir}",
                proto_path,
            ]
            subprocess.check_call(cmd)
            print(f"Generated Python code for {proto_file}")

        # Fix imports in generated files
        for proto_file in proto_files:
            base_name = os.path.splitext(proto_file)[0]
            pb2_file = os.path.join(generated_dir, f"{base_name}_pb2.py")
            pb2_grpc_file = os.path.join(generated_dir, f"{base_name}_pb2_grpc.py")

            # Fix imports in pb2 files
            if os.path.exists(pb2_file):
                with open(pb2_file, "r") as f:
                    content = f.read()

                # Replace direct imports with package imports
                content = content.replace(
                    "import common_pb2 as common__pb2",
                    "from . import common_pb2 as common__pb2",
                )

                with open(pb2_file, "w") as f:
                    f.write(content)

            # Fix imports in pb2_grpc files
            if os.path.exists(pb2_grpc_file):
                with open(pb2_grpc_file, "r") as f:
                    content = f.read()

                # Replace direct imports with package imports
                content = content.replace(
                    "import common_pb2 as common__pb2",
                    "from . import common_pb2 as common__pb2",
                )
                content = content.replace(
                    "import file_audit_pb2 as file__audit__pb2",
                    "from . import file_audit_pb2 as file__audit__pb2",
                )
                content = content.replace(
                    "import block_chain_pb2 as block__chain__pb2",
                    "from . import block_chain_pb2 as block__chain__pb2",
                )

                with open(pb2_grpc_file, "w") as f:
                    f.write(content)

    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    generate_proto()
