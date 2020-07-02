#!/bin/bash
set -e
sudo yum-config-manager --enable epel
sudo amazon-linux-extras install ansible2 -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2