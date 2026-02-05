FROM php:7.4-apache
COPY src/ /var/www/html/
RUN echo "AG{LFI_Tr4v3rs4l_M4st3r_2026}" > /etc/secret_flag.txt
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
