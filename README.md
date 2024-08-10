# Blockchain-Project

## How to Build the Docker Containers and Docker Network

**Pull Docker images from Dockerhub**

In your terminal run the following:

```shell
docker pull kylelee1/dns_health_seed_image:latest
docker pull kylelee1/health_node_image:latest
```

You should now have two new docker images on your computer called
`dns_health_seed` and `health_node_image`. You may have to authenticate by
running `docker login` before you're able to pull the images down.

**Build the network**

Next, to create the docker container network run:

```shell
docker network create health-net
```

This will create the `health-net` network that the individual docker containers
will use to communicate with each other.

**Build the containers**

Within the `dns_seed_server` and `full_node_server` directories are shell
scripts called `build.sh`

First, build the `dns_seed_server` by doing the following:

```shell
cd services/dns_seed_server
./build.sh
```

Similarly for the `health_service` VO nodes:

```shell
cd services/full_node_server
./build.sh
```

The `build.sh` scripts delete any existing containers with the same names,
builds the images, and then runs the containers.
