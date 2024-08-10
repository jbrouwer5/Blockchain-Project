docker rm -f HEALTH_NODE_1 HEALTH_NODE_2 HEALTH_NODE_3
docker build -t health_node_image .
docker run -d --name HEALTH_NODE_1 --network health-net health_node_image
docker run -d --name HEALTH_NODE_2 --network health-net health_node_image
docker run -d --name HEALTH_NODE_3 --network health-net health_node_image
