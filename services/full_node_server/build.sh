docker rm -f FULL_NODE_1 FULL_NODE_2 FULL_NODE_3
docker build -t full_node_image .
docker run -d --name FULL_NODE_1 --network blockchain-net full_node_image
docker run -d --name FULL_NODE_2 --network blockchain-net full_node_image
docker run -d --name FULL_NODE_3 --network blockchain-net full_node_image
