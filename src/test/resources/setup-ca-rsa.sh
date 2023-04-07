#!/bin/bash

_passowrd="password"

_ca_root_name="Test-Root-CA"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${_ca_root_name}.pem" -pass pass:${_passowrd}
openssl req -x509 -new -nodes -key "${_ca_root_name}.pem" -sha256 -days 3650 -out "${_ca_root_name}.crt" -subj "/C=AT/CN=${_ca_root_name}"

_ca_inter_name="Test-Intermediate-CA"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${_ca_inter_name}.pem" -pass pass:${_passowrd}
openssl req -x509 -new -nodes -CA "${_ca_root_name}.crt" -CAkey "${_ca_root_name}.pem" -key "${_ca_inter_name}.pem" -sha256 -days 3000 -out "${_ca_inter_name}.crt" -subj "/C=AT/CN=${_ca_inter_name}"

_webserver_name="www.doesnotexist.org"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${_webserver_name}.pem" -pass pass:${_passowrd}
openssl req -x509 -new -nodes -CA "${_ca_inter_name}.crt" -CAkey "${_ca_inter_name}.pem" -key "${_webserver_name}.pem" -sha256 -days 366 -out "${_webserver_name}.crt" -subj "/CN=${_webserver_name}" -addext "basicConstraints=CA:FALSE" -addext "subjectAltName=DNS:${_webserver_name}"

# we use a config file in a variable to avoid having a basicConstraints extension in the certificate
_openssl_config="
[req]
distinguished_name=dn
[dn]
[ext]
subjectAltName=DNS:${_webserver_name}
"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${_webserver_name}.pem" -pass pass:${_passowrd}
openssl req -config <(echo "$_openssl_config") -x509 -new -nodes -CA "${_ca_inter_name}.crt" -CAkey "${_ca_inter_name}.pem" -key "${_webserver_name}.pem" -sha256 -days 366 -out "${_webserver_name}.crt" -subj "/CN=${_webserver_name}" -extensions ext