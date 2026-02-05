FROM php:7.4-apache-alpine

# Set up the challenge environment
WORKDIR /var/www/html/

# Create the logs directory and a few decoy logs
RUN mkdir -p logs && \
    echo "Alignment successful: 0.003 arcsec offset" > logs/alignment_2023.log && \
    echo "Solar flare detected. Sensors throttled." > logs/solar_event_01.log && \
    echo "Calibration complete. All systems nominal." > logs/calibration.txt

# The hidden flag on the server root
RUN echo "AG{LFI_1n_th3_St4rs_8ce3}" > /flag.txt

# Copy the vulnerable source
COPY index.php .

# Adjust permissions
RUN chown -R www-data:www-data /var/www/html/

EXPOSE 80
