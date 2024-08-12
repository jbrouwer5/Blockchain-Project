# Blockchain-Project

### Docker Instructions

- In the services/dns_seed_server directory run ./build.sh
- run docker exec -it `<docker container id of the container that was just generated> ` sh
- now inside of the docker container, run "python3 dns_seed_server.py"
- Your dns seed server is now running
- In a new terminal window, cd into the services/full_node_server directory and run ./build.sh
- This will generate three new docker containers
- For each one, do the following
  - run docker exec -it `<docker container id of the container that was just generated> ` sh
  - run "python3 server.py"
  - If you're having trouble using exec to access the containers, you can also do <docker run -it --name HEALTH_NODE_1 --network health-net health_node_image /bin/sh>
- Now you have a dns server and three full node servers which are all aware of eachother

### Proto Instructions 

- If you make changes to the .proto file and need to regenerate the message classes, run "python3 -m grpc_tools.protoc -I=. --python_out=. --grpc_python_out=. health_service.proto" locally or "python -m grpc_tools.protoc -I=. --python_out=. --grpc_python_out=. health_service.proto" in the docker container
