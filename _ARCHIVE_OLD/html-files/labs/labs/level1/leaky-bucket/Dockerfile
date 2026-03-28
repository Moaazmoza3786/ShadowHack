FROM php:7.4-apache
RUN apt-get update && apt-get install -y zip
COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
