FROM php:8.1-apache

RUN docker-php-ext-install mysqli pdo pdo_mysql
RUN a2enmod rewrite

# Force UTF-8 at Apache level + enable AllowOverride so .htaccess works
RUN printf '<Directory /var/www/html>\n    AllowOverride All\n    Options -Indexes +FollowSymLinks\n    AddDefaultCharset UTF-8\n</Directory>\nAddDefaultCharset UTF-8\n' \
    > /etc/apache2/conf-available/vulnmart.conf \
 && a2enconf vulnmart

# Force UTF-8 at PHP level
RUN echo "default_charset = UTF-8" >> /usr/local/etc/php/php.ini

COPY ./src /var/www/html/

RUN chown -R www-data:www-data /var/www/html
RUN find /var/www/html -type d -exec chmod 755 {} \;
RUN find /var/www/html -type f -exec chmod 644 {} \;
