# webapps
Web applications

### Trouble shooting and logs
    /var/log/uwsgi.log         # Has startup and operation data for the Flask application and uwsgi
    /var/log/nginx/access.log  # HTTP access and error logs
    /var/log/auth.log          # SSH and other connection attempts

### Update Linux
    sudo -- sh -c 'apt-get update; apt-get upgrade -y; apt-get dist-upgrade -y; apt-get autoremove -y; apt-get autoclean -y'

### Validate JSON files
    cat file.json | jq
    python -m jsontool < file.json

### Setup environment
    sudo chown ubuntu /var/www/app
    cp -R * /var/www/app

### Setup Nginx
    rm /etc/nginx/sites-enabled/default
    cp nginx/webapp.conf /etc/nginx/sites-available/
    ln -s /etc/nginx/sites-available/webapp.conf /etc/nginx/sites-enabled/webapp.conf
    cp nginx/uwsgi.ini /var/www/app/
    echo "daemon off;" >> /etc/nginx/nginx.conf

### /etc/rc.local
    /home/ubuntu/.local/bin/uwsgi --ini /var/www/app/uwsgi.ini --uid ubuntu --gid ubuntu --daemonize /var/log/uwsgi.log

### Build the Docker container
    docker build -t webapp .

### Run the Docker container
    docker run --rm -e AWS_DEFAULT_REGION=us-west-2 -v mycredentialsfile:/home/frosty/.aws/credentials:ro  -p 80:80 --name recipes frosty308/recipes

### Various commands to get information and interact
    docker ps
    docker stop <CONTAINER ID>
    docker inspect <CONTAINER ID>
    docker exec -t -i <CONTAINER ID> /bin/bash
    docker rm $(docker ps -a -f status=exited -q)
    docker network inspect bridge

### Show images, remove dangling images
    docker images
    docker rmi $(docker images -f "dangling=true" -q)

### Push to Docker repository
    docker images
    docker tag <IMAGE ID> frosty308/recipes:latest
    docker login -u username -p password
    docker push frosty308/recipes
    docker logout

### Upload photo
    image.py -f TomatoCarrotChicken.jpg -r 0 process
    image.py -f TomatoCarrotChicken.jpg -r 0 upload
