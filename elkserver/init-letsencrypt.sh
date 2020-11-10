#!/bin/bash

if ! [ -x "$(command -v docker-compose)" ]; then
  echo 'Error: docker-compose is not installed.' >&2
  exit 1
fi

domain=$(cat ./mounts/redelk-config/etc/redelk/config.json | jq -r .external_domain)
rsa_key_size=4096
data_path="./mounts/certbot"
email="$(cat ./mounts/redelk-config/etc/redelk/config.json | jq -r .le_email)" # Adding a valid address is strongly recommended
staging=0 # Set to 1 if you're testing your setup to avoid hitting request limits
compose_file=redelk-full.yml

# if [ -d "$data_path" ]; then
#   read -p "Existing data found for $domains. Continue and replace existing certificate? (y/N) " decision
#   if [ "$decision" != "Y" ] && [ "$decision" != "y" ]; then
#     exit
#   fi
# fi


# if [ ! -e "$data_path/conf/options-ssl-nginx.conf" ] || [ ! -e "$data_path/conf/ssl-dhparams.pem" ]; then
#   echo "### Downloading recommended TLS parameters ..."
#   mkdir -p "$data_path/conf"
#   curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf > "$data_path/conf/options-ssl-nginx.conf"
#   curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem > "$data_path/conf/ssl-dhparams.pem"
#   echo
# fi

echo "### Creating dummy certificate for $domain ..."
path="/etc/letsencrypt/live/$domain"
mkdir -p "$data_path/conf/live/$domain"
docker-compose -f $compose_file run --rm --entrypoint "\
  openssl req -x509 -nodes -newkey rsa:$rsa_key_size -days 365\
    -keyout '$path/privkey.pem' \
    -out '$path/fullchain.pem' \
    -subj '/CN=${domain}'" certbot
echo


echo "### Starting nginx ..."
docker-compose -f $compose_file up --force-recreate -d nginx
echo

# echo "### Deleting dummy certificate for $domain ..."
# docker-compose -f $compose_file run --rm --entrypoint "\
#   rm -Rf /etc/letsencrypt/live/$domain && \
#   rm -Rf /etc/letsencrypt/archive/$domain && \
#   rm -Rf /etc/letsencrypt/renewal/$domain.conf" certbot
# echo


echo "### Requesting Let's Encrypt certificate for $domain ..."
# #Join $domains to -d args
# domain_args=""
# for domain in "${domains[@]}"; do
#   domain_args="$domain_args -d $domain"
# done

# Select appropriate email arg
case "$email" in
  "") email_arg="--register-unsafely-without-email" ;;
  *) email_arg="--email $email" ;;
esac

# Enable staging mode if needed
if [ $staging != "0" ]; then staging_arg="--staging"; fi

docker-compose -f $compose_file run --rm --entrypoint "\
  certbot certonly --webroot -w /var/www/certbot \
    $staging_arg \
    $email_arg \
    -d $domain \
    --rsa-key-size $rsa_key_size \
    --agree-tos \
    --force-renewal -n" certbot
echo

echo "### Reloading nginx ..."
docker-compose -f $compose_file exec nginx nginx -s reload
