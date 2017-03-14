# Makefile to simplify common operations

DOCKER_REPO=frosty308/webapps
docker:
	sudo docker build -t webapp .

push:
	# Need to be logged in for push to Docker Cloud
	# sudo docker login -u username -p password
	# sudo docker tag <image id> frosty308/recipies:latest
	sudo docker push frosty308/recipes

run:
	#sudo docker run -e AWS_DEFAULT_REGION=us-west-2 -v /home/frosty/.aws/credentials:/root/.aws/credentials:ro --rm --name webapp webapp
	sudo docker run -d -e AWS_DEFAULT_REGION=us-west-2 -v /home/frosty/.aws/credentials:/root/.aws/credentials:ro -p 8080:80 --name webapp webapp
