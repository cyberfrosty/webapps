FROM ubuntu:16.04

LABEL maintainer Alan Frost <frosty.alan@gmail.com>
LABEL com.cyberfrosty.version="0.0.1-beta"
LABEL vendor="Frosty Security"
LABEL com.cyberfrosty.release-date="2017-02-12"

# Nginx, UWSGI Plugin, Python development libraries
RUN apt-get update && \
    apt-get -y install \
    curl \
    python-dev \
    libmysqlclient-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    nginx \
    supervisor \
    uwsgi \
    && rm -rf /var/lib/apt/lists/*


# Install pip
ENV PYTHON_PIP_VERSION 9.0.1
RUN curl -SL 'https://bootstrap.pypa.io/get-pip.py' | python \
    && pip install --upgrade pip==$PYTHON_PIP_VERSION

# Install uwsgi
RUN pip install uwsgi

# Copy Requirements and Install
# This ensures that after initial build modules will be cached
COPY requirements.txt /var/www/app/
RUN pip install -r /var/www/app/requirements.txt

# Install and setup supervisor
RUN pip install supervisor
RUN mkdir -p /var/log/supervisor
COPY nginx/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Setup Nginx
RUN rm /etc/nginx/sites-enabled/default
COPY nginx/webapp.conf /etc/nginx/sites-available/
RUN ln -s /etc/nginx/sites-available/webapp.conf /etc/nginx/sites-enabled/webapp.conf
COPY nginx/uwsgi.ini /var/www/app/
RUN echo "daemon off;" >> /etc/nginx/nginx.conf

# Copy Application
COPY . /var/www/app

# Expose the nginx web server port
EXPOSE 80

# Start nginx and uwsgi via supervisord
CMD /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
