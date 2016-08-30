JENOVA
======

**You can help build this...**

---------

Development Environment
-------------

This instructions will help you to build the development environment.

> - Requirements: 
> -- git, 
> --python (2.7) and python-dev, 
> --mysql-client, 
> --docker(engine/compose/machine)...
> - Clone this repository;
> - Generate a Self-Signed Certificate in src\jenova\ssl
> ```
> openssl req \
       -newkey rsa:2048 -nodes -keyout mydomain.key \
       -x509 -days 365 -out mydomain.crt
> ```
> - Navigate in src folder and run:
>  ```docker-compose build && docker-compose up``` 

----------

Docker Images
-------------

If you want only run Jenova in your server,  docker pull on this image available in [Docker Hub](https://hub.docker.com/r/inova/jenova/).