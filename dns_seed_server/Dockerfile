# Dockerfile for DNS_SEED server
FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir grpcio grpcio-tools

# Generate Full Node gRPC files from the proto file (if necessary)
RUN python -m grpc_tools.protoc -I=. --python_out=. --grpc_python_out=. dns_seed.proto

EXPOSE 12345

CMD ["python", "-u", "dns_seed_server.py"]

