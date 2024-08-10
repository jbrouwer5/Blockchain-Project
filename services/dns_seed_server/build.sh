docker rm -f dns_seed
docker build -t dns_seed_image .
docker run -d --name dns_seed -p 12345:12345 --network blockchain-net dns_seed_image
