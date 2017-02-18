# Makefile to simplify common operations

DOCKER_REPO=frosty308/webapps
docker:
	sudo docker build -t webapp .

push:
	# Need to be logged in for push to Docker Cloud
	# sudo docker login -u username -p password
	sudo docker tag webapp:latest $(DOCKER_REPO)
	sudo docker push $(DOCKER_REPO)

run:
	sudo docker run -d -e AWS_DEFAULT_REGION=us-west-2 -v /home/frosty/.aws/credentials:/root/.aws/credentials:ro --rm --name webapp $(DOCKER_REPO)
