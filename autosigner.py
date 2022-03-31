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
from secret import secret_key


# Basic logging config
logging.basicConfig(
    filename="/tmp/puppet-autosign.log",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG,
)

ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin:/opt/puppetlabs/bin"}
PROJECT_NUMBERS = [197490292429,369653172086,486936945290,868921898489,705126435018,117370217113]


def check_payload(payload):
    try:
        project_number = payload["google"]["compute_engine"]["project_number"]
    except KeyError:
        logging.error("Could not get project number from payload")
        exit(1)

    if time.time() > payload["exp"]:
        logging.error("Token has expired")
        return False
    elif project_number in PROJECT_NUMBERS:
        return True
    else:
        logging.error("Project ID not recognised")
        return False


def jail_validation(node_fqdn, challenge_password):
    if challenge_password == secret_key:
        exit(0)
    else:
        exit(1)


def gcp_instance_validation(node_fqdn, challenge_password, audience):
    payload = id_token.verify_token(challenge_password, request=Request(), audience=audience)

    if check_payload(payload):
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
        jail_validation(args.node_fqdn, challenge_password)
    else:
        gcp_instance_validation(args.node_fqdn, challenge_password, audience)


if __name__ == "__main__":
    main(sys.stdin.buffer.read())
