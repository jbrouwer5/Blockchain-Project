docker rm -f dns_health_seed
docker build -t dns_health_seed_image .
docker network create -d bridge health-net
docker run -d --name dns_health_seed -p 12345:12345 --network health-net dns_health_seed_image
