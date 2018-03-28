#!/usr/bin/env python3.5

# Std lib
import os
import sys
import time
import logging
import argparse
import subprocess

# Installed 3rd party libs
import google.auth.transport.requests
from google.oauth2 import id_token

# Local python files
from local import project_numbers


# Logging configuration
logger = logging.getLogger('autosigner')
log_handler = logging.FileHandler('/tmp/puppet-autosign.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
log_handler.setFormatter(formatter)
logger.addHandler(log_handler)
logger.setLevel(logging.DEBUG)


# Set up the parsing of the hostname which will be used to create the temp file
parser = argparse.ArgumentParser(description='Parse the hostname')
parser.add_argument('hostname', type=str)
cmdargs = parser.parse_args()


# This needs to exist so that openssl can parse it
tmp_file = '/tmp/{0}'.format(cmdargs.hostname)
# This is going to be http://<fqdn>.  I don't think that it actually matters what
# the content of it is, except that it's the same as was used at the other end
# and it needs to have a scheme.
audience = 'http://{}'.format(cmdargs.hostname)


def save_cert(stdin, tmp_file):
    # We need to save this as a file so that the system tools can
    # access it
    with open(tmp_file, 'wb') as w:
        w.write(stdin)


def get_challenge_password():

    # There's not a python library to do this so we need to
    # rely on the system tools to parse this for us.
    # I've hardcoded the path to openssl here ... it seems to
    # be the default location for the two *NIX OSes we use
    csr = subprocess.Popen([
        '/usr/bin/openssl',
        'req',
        '-text',
        '-noout',
        '-in',
        tmp_file
    ], stdout=subprocess.PIPE)
    cp_line = subprocess.Popen([
        'grep',
        'challengePassword',
    ], stdin=csr.stdout, stdout=subprocess.PIPE)
    token = subprocess.check_output([
        'cut',
        '-f2-',
        '-d:'
    ], stdin=cp_line.stdout)

    # Clean up the temp file as we don't want the OS drive filling
    # up with these files and also we don't want to leave challenge
    # passwords littering the /tmp directory
    return token.decode('utf-8').replace('\n','')


def check_jwt(audience):
    # This function checks the validity of the token and audience and returns a
    # dictionary
    request = google.auth.transport.requests.Request()
    try:
        token = get_challenge_password()
        payload = id_token.verify_token(token, request=request,
                                        audience=audience)
        return payload
    except ValueError:
        with open(tmp_file, 'r') as tf:
            subprocess.Popen([
                '/usr/local/bin/autosign-validator',
                cmdargs.hostname], stdin=tf
            ).communicate()
        os.remove(tmp_file)
        exit(1)


def check_payload(payload):
    os.remove(tmp_file)
    if payload['google']['compute_engine']['project_number'] not in project_numbers:
        print('Project ID not recognised')
        exit(1)
    elif time.time() > payload['exp']:
        print('Token has expired')
        exit(1)
    else:
        print(payload)
        exit(0)


def main(stdin):
    save_cert(stdin,tmp_file)
    payload = check_jwt(audience)
    check_payload(payload)


if __name__ == "__main__":
    pass
    #### Run a function
    main(sys.stdin.buffer.read())
