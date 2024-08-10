# Dockerfile for Full Node

# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the full_node_server files into the container
COPY . /app

# Install necessary dependencies
RUN pip install --no-cache-dir grpcio grpcio-tools sqlalchemy

# Generate Health Service Node gRPC files from the proto file (if necessary)
RUN python -m grpc_tools.protoc -I=. --python_out=. --grpc_python_out=. health_service.proto

# Seed the database with data
RUN python seed_db.py

# Expose the necessary port
EXPOSE 58333

# Run the Full Node server
CMD ["python", "-u", "server.py"]

