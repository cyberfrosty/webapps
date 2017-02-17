Running Fullstack AWS Web Applications with Amazon Lightsail
============================================================
Amazon Lightsail is an easy and inexpensive way to set up a Virtual Private Server. Access
to AWS resources from an existing AWS account and migration to a load balanced production
environment is straightforward. Using Docker with Amazon Lightsail makes it super simple
to build, test and deploy web applications using any stack.

Setup Steps
-----------
Sign up for Amazon Lightsail

Generate ssh keys
```
ssh-keygen -t rsa
chmod 400 id_rsa
cp id_rsa ~/.ssh
```
Create an instance: base OS Ubuntu 16.04

Upload SSH public key: id_rsa.pub

Specify launch script to update and install Docker service
```
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates
sudo apt-key adv --keyserver hkp://ha.pool.sks-keyservers.net:80 \
             --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
echo "deb https://apt.dockerproject.org/repo ubuntu-xenial main" | \
             sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y linux-image-extra-$(uname -r) linux-image-extra-virtual
sudo apt-get install -y docker-engine
sudo service docker start
```

Start instance and note the static IP address assigned

SSH into the instance 
```
ssh ubuntu@54.112.119.1
```

Update and restart as needed using
```
sudo apt-get update
sudo apt-get upgrade
sudo reboot
```

```
sudo docker login -u username -p password
sudo docker pull frosty308/webapps
```
Run the application with your AWS credentials and config information provided as environment variables
```
sudo docker run -d -e AWS_DEFAULT_REGION=us-west-2 -e AWS_ACCESS_KEY_ID=<keyid> -e  AWS_SECRET_ACCESS_KEY=<key> --rm --name ionu-nginx frosty308/webapps
```
Alternatively you can run the application with your AWS credentials and config information from a mounted file
```
docker run -d -e AWS_DEFAULT_REGION=us-west-2 -v mycredentialsfile:/root/.aws/credentials:ro --rm --name ionu-nginx frosty308/webapps
```
