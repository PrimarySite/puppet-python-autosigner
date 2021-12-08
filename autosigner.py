#!/usr/bin/env python3

# Standard Library
import argparse
import logging
import subprocess
import sys
import time

# 3rd-party
from cryptography import x509
from google.auth.transport.requests import Request
from google.oauth2 import id_token

# Project
from settings import project_numbers

# Basic logging config
logging.basicConfig(
    filename="/tmp/puppet-autosign.log",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG,
)

ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin:/opt/puppetlabs/bin"
}


def check_existing_cert(hostname):
    logging.info(f"Hostname is: {hostname}")
    try:
        if subprocess.check_output([f"puppet cert list {hostname}"], stderr=subprocess.STDOUT, shell=True, env=ENV):
            subprocess.run([f"puppet cert clean {hostname}"], stderr=subprocess.STDOUT, shell=True, env=ENV)
            logging.info(f"Cleaned existing cert for {hostname}")
    except subprocess.CalledProcessError as error:
        logging.error(error.cmd)
        logging.error(error.output)
        logging.error(error.returncode)
        logging.error(error.stdout)


def check_payload(payload):
    try:
        project_number = payload["google"]["compute_engine"]["project_number"]
    except KeyError:
        logging.error("Key error in payload!")
        exit(1)

    if project_number not in project_numbers:
        logging.error("Project ID not recognised")
        return False
    elif time.time() > payload["exp"]:
        logging.error("Token has expired")
        return False
    else:
        return True


def jail_validation(node_fqdn, csr):
    ruby_validator = subprocess.run(["autosign-validator", node_fqdn], input=csr, stderr=subprocess.STDOUT, shell=True, env=ENV)

    if ruby_validator.returncode == 0:
        check_existing_cert(node_fqdn)

    exit(ruby_validator.returncode)


def gcp_instance_validation(node_fqdn, challenge_password, audience):
    request = Request()
    payload = id_token.verify_token(challenge_password, request=request, audience=audience)

    if check_payload(payload):
        check_existing_cert(node_fqdn)
        exit(0)
    else:
        exit(1)


def decode_csr(csr):
    crypto_csr = x509.load_pem_x509_csr(csr)
    challenge_password = crypto_csr.get_attribute_for_oid(x509.oid.AttributeOID.CHALLENGE_PASSWORD)
    return challenge_password


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("node_fqdn")
    args = parser.parse_args()
    return args


def main(stdin):
    args = get_args()
    audience = f"http://{args.node_fqdn}"
    challenge_password = decode_csr(stdin)

    if "jail" in args.node_fqdn:
        jail_validation(args.node_fqdn, stdin)
    else:
        gcp_instance_validation(args.node_fqdn, challenge_password, audience)


if __name__ == "__main__":
    main(sys.stdin.buffer.read())
