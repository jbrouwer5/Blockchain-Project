# Dockerfile for Full Node

# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the full_node_server files into the container
COPY . /app

# Install necessary dependencies
RUN pip install --no-cache-dir grpcio grpcio-tools

# Generate Full Node gRPC files from the proto file (if necessary)
RUN python -m grpc_tools.protoc -I=. --python_out=. --grpc_python_out=. full_node.proto

# Expose the necessary port
EXPOSE 58333

# Run the Full Node server
CMD ["python", "-u", "full_node_server.py"]

