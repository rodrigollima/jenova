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

CREATE TABLE `jenovadb`.`user_options_mapping` (
  `id` INT NOT NULL,
  `resource_option_id` INT NULL,
  `user_id` INT NULL,
  PRIMARY KEY (`id`));

CREATE TABLE `jenovadb`.`resource_options` (
  `id` INT NOT NULL,
  `resource` VARCHAR(100) NULL,
  `name` VARCHAR(100) NULL,
  PRIMARY KEY (`id`));

CREATE TABLE `jenovadb`.`options` (
  `id` INT NOT NULL,
  `resources_options_id` INT NOT NULL,
  `user_id` INT NOT NULL,
  PRIMARY KEY (`id`));

ALTER TABLE `jenovadb`.`user_options_mapping` 
DROP COLUMN `id`,
DROP PRIMARY KEY;
