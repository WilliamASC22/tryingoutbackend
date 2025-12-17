openssl req -x509 -newkey rsa:4096 -keyout ./nginx/private.key -out ./nginx/cert.pem -days 365 -sha256 -nodes -subj "/C=US"

openssl genrsa -out ./authentication/jwtRS256.key 2048

openssl rsa -in ./authentication/jwtRS256.key -pubout -out ./jwtRS256.key.pem