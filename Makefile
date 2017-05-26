# Makefile to simplify common operations

DOCKER_REPO=frosty308/webapps
docker:
	docker build -t webapp .

push:
	# Need to be logged in for push to Docker Cloud
	# docker login -u username -p password
	# docker tag <image id> frosty308/recipies:latest
	docker push frosty308/recipes

run:
	#docker run -e AWS_DEFAULT_REGION=us-west-2 -v /home/frosty/.aws/credentials:/root/.aws/credentials:ro --rm --name webapp webapp
	docker run -d --restart=always -e AWS_DEFAULT_REGION=us-west-2 -v /home/frosty/.aws/credentials:/root/.aws/credentials:ro -p 80:80 --name webapp webapp

test:
	python crypto.py
