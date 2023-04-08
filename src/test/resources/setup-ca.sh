#!/bin/bash

generate_pki() {
    openssl genpkey -algorithm ${_algorithm} -pkeyopt "${_algorithm_opt}" -out "${_ca_root_name}.pem" -pass pass:${_passowrd}
    openssl req -x509 -new -nodes -key "${_ca_root_name}.pem" -sha256 -days 3650 -out "${_ca_root_name}.crt" -subj "/C=AT/CN=${_ca_root_name}"

    _ca_inter_name="Test-Intermediate-CA-${_algorithm}"
    openssl genpkey -algorithm ${_algorithm} -pkeyopt "${_algorithm_opt}" -out "${_ca_inter_name}.pem" -pass pass:${_passowrd}
    openssl req -x509 -new -nodes -CA "${_ca_root_name}.crt" -CAkey "${_ca_root_name}.pem" -key "${_ca_inter_name}.pem" -sha256 -days 3000 -out "${_ca_inter_name}.crt" -subj "/C=AT/CN=${_ca_inter_name}"

    # we use a config file in a variable to avoid having a basicConstraints extension in the certificate
    _openssl_config="
    [req]
    distinguished_name=dn
    [dn]
    [ext]
    subjectAltName=DNS:${_webserver_name}
    "
    openssl genpkey -algorithm ${_algorithm} -pkeyopt "${_algorithm_opt}" -out "${_webserver_name}.pem" -pass pass:${_passowrd}
    openssl req -config <(echo "$_openssl_config") -x509 -new -nodes -CA "${_ca_inter_name}.crt" -CAkey "${_ca_inter_name}.pem" -key "${_webserver_name}.pem" -sha256 -days 366 -out "${_webserver_name}.crt" -subj "/CN=${_webserver_name}" -extensions ext

    cat "${_webserver_name}.pem" "${_webserver_name}.crt" "${_ca_inter_name}.crt" "${_ca_root_name}.crt" > "${_webserver_name}-keystore.pem"
} 

_passowrd="password"
_algorithm="RSA"
_algorithm_opt="rsa_keygen_bits:4096"
_ca_root_name="Test-Root-CA-${_algorithm}"
_webserver_name="www.doesnotexist.org-${_algorithm}"

generate_pki

_passowrd="password"
_algorithm="EC"
_algorithm_opt="ec_paramgen_curve:P-256"
_ca_root_name="Test-Root-CA-${_algorithm}"
_webserver_name="www.doesnotexist.org-${_algorithm}"

generate_pki
