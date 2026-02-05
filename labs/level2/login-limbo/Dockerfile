FROM php:7.4-apache
RUN apt-get update && apt-get install -y sqlite3 libsqlite3-dev
RUN docker-php-ext-install pdo pdo_sqlite
COPY index.php /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
