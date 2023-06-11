#!/bin/bash

generate_pem_alias() {
    for i in "$@"
    do 
        echo "Alias: ${i%.*}"
        cat ${i}
    done
}

generate_pki() {
    rm "${_ca_root_name}.pem"
    openssl genpkey -algorithm ${_algorithm} -pkeyopt "${_algorithm_opt}" -out "${_ca_root_name}.pem" -pass pass:${_passowrd}

    rm "${_ca_root_name}.crt"
    openssl req -x509 -new -nodes -key "${_ca_root_name}.pem" -sha256 -days 3650 -out "${_ca_root_name}.crt" -subj "/C=AT/CN=${_ca_root_name}"

    _ca_inter_name="Test-Intermediate-CA-${_algorithm}"
    rm "${_ca_inter_name}.pem"
    openssl genpkey -algorithm ${_algorithm} -pkeyopt "${_algorithm_opt}" -out "${_ca_inter_name}.pem" -pass pass:${_passowrd}

    rm "${_ca_inter_name}.crt"
    openssl req -x509 -new -nodes -CA "${_ca_root_name}.crt" -CAkey "${_ca_root_name}.pem" -key "${_ca_inter_name}.pem" -sha256 -days 3000 -out "${_ca_inter_name}.crt" -subj "/C=AT/CN=${_ca_inter_name}"

    # we use a config file in a variable to avoid having a basicConstraints extension in the certificate
    _openssl_config="
    [req]
    distinguished_name=dn
    [dn]
    [ext]
    subjectAltName=DNS:${_webserver_dns_name},DNS:localhost
    "

    rm "${_certificate_name}.pem"
    openssl genpkey -algorithm ${_algorithm} -pkeyopt "${_algorithm_opt}" -out "${_certificate_name}.pem" -pass pass:${_passowrd}

    rm "${_certificate_name}-enc.pem"
    openssl pkey -in "${_certificate_name}.pem" -out "${_certificate_name}-enc.pem" -passout pass:${_passowrd} -aes128

    rm "${_certificate_name}.crt"
    openssl req -config <(echo "$_openssl_config") -x509 -new -nodes -CA "${_ca_inter_name}.crt" -CAkey "${_ca_inter_name}.pem" -key "${_certificate_name}.pem" -sha256 -days 366 -out "${_certificate_name}.crt" -subj "/CN=${_certificate_name}" -extensions ext

    cat "${_certificate_name}.pem" "${_certificate_name}.crt" "${_ca_inter_name}.crt" "${_ca_root_name}.crt" > "${_certificate_name}-keystore.pem"
    generate_pem_alias "${_certificate_name}.pem" "${_certificate_name}.crt" "${_ca_inter_name}.crt" "${_ca_root_name}.crt" | sed "s/Alias: .*/Alias: ${_certificate_name}/" > "${_certificate_name}-keystore-alias.pem"
    generate_pem_alias "${_certificate_name}-enc.pem" "${_certificate_name}.crt" "${_ca_inter_name}.crt" "${_ca_root_name}.crt" | sed "s/Alias: .*/Alias: ${_certificate_name}/" > "${_certificate_name}-enc-keystore.pem"

    cat "${_ca_inter_name}.crt" "${_ca_root_name}.crt" > "${_certificate_name}-truststore.pem"
} 

_passowrd="password"
_algorithm="RSA"
_algorithm_opt="rsa_keygen_bits:4096"
_ca_root_name="Test-Root-CA-${_algorithm}"
_webserver_dns_name="www.doesnotexist.org"
_certificate_name="${_webserver_dns_name}-${_algorithm}"

generate_pki

generate_pem_alias lets-encrypt-ca-R3.crt lets-encrypt-root-ISRG-Root-X1.crt Test-Intermediate-CA-RSA.crt Test-Root-CA-RSA.crt > ca-truststore.pem

_passowrd="password"
_algorithm="EC"
_algorithm_opt="ec_paramgen_curve:P-256"
_ca_root_name="Test-Root-CA-${_algorithm}"
_webserver_dns_name="www.doesnotexist.org"
_certificate_name="${_webserver_dns_name}-${_algorithm}"

generate_pki
