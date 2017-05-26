Running AWS Web Applications with Amazon Lightsail
==================================================
Amazon Lightsail is an easy and inexpensive way to set up a Virtual Private Server. Access
to AWS resources from an existing AWS account and migration to a load balanced production
environment is straightforward. Using Docker with Amazon Lightsail makes it super simple
to build, test and deploy web applications using any stack.

Setup Steps
-----------
* Sign up for [Amazon Lightsail](https://amazonlightsail.com) or Login to AWS, jump to Lightsail

* Generate ssh keys
```
ssh-keygen -t rsa
chmod 400 id_rsa
cp id_rsa ~/.ssh
```
* Create an instance, select “Base OS” and the option for “Ubuntu 16.04”

* Upload SSH public key: id_rsa.pub

* Specify launch script to update and install Docker service [via David Kryzaniak's blog](https://davekz.com/docker-on-lightsail/)
```
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates
sudo apt-key adv --keyserver hkp://ha.pool.sks-keyservers.net:80 \
             --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
echo "deb https://apt.dockerproject.org/repo ubuntu-xenial main" | \
             tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y linux-image-extra-$(uname -r) linux-image-extra-virtual
sudo apt-get install -y docker-engine
sudo service docker start
```

* Start instance and note the static IP address assigned

* SSH into the instance, using command line or from AWS console
```
ssh ubuntu@54.86.117.1
```

* Update and restart as needed using, stop and reboot can also be done via AWS console
```
sudo apt-get update
sudo apt-get upgrade
sudo reboot
```

* Login to docker and pull (or just run) the image
```
docker login -u username -p password
docker pull frosty308/webapps
```
* Run the application with your AWS credentials and config information provided as environment variables
```
docker run -d -e AWS_DEFAULT_REGION=us-west-2 -e AWS_ACCESS_KEY_ID=<keyid> -e  AWS_SECRET_ACCESS_KEY=<key> -p 80:80 --name webapp-nginx frosty308/recipes
```
* Alternatively you can run the application with your AWS credentials and config information from a mounted file
```
docker run -d -e AWS_DEFAULT_REGION=us-west-2 -v mycredentialsfile:/root/.aws/credentials:ro -p 80:80 --name webapp-nginx frosty308/recipes
```
