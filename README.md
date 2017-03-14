# webapps
Web applications

### Build the Docker container
docker build -t webapp .

### Run the Docker container
docker run --rm -e AWS_DEFAULT_REGION=us-west-2 -v mycredentialsfile:/home/frosty/.aws/credentials:ro  -p 8080:80 --name recipes frosty308/recipes

### Various commands to get information and interact
docker ps
docker stop <CONTAINER ID>
docker inspect <CONTAINER ID>
docker exec -t -i <CONTAINER ID> /bin/bash
docker rm $(docker ps -a -f status=exited -q)

### Show images, remove dangling images
docker images
docker rmi $(docker images -f "dangling=true" -q)

### Push to Docker repository
docker images
docker tag <IMAGE ID> frosty308/recipes:latest
docker login -u username -p password
docker push frosty308/recipes
docker logout
