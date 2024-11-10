# hashmac_lab1


Build the Docker image
```sh
docker-compose -p hashmac build
```

Run the Docker Container with Arguments
```sh
docker-compose run --rm lab1 --log-level DEBUG --iterations 1
```

Clear builds
```sh
docker-compose down --volumes --remove-orphans
docker rmi $(docker images -q --filter=reference='hashmac-lab1')
docker volume prune -f
```
