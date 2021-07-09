#!/usr/bin/env python3

# Std lib
import os
import sys
import time
import logging
import argparse
import subprocess

# Installed 3rd party libs
from google.auth.transport.requests import Request
from google.oauth2 import id_token

# Local python files
from local import project_numbers

# Basic logging config
logging.basicConfig(
    filename='/tmp/puppet-autosign.log',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG,
)

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


def check_existing_cert(hostname):
    logging.info(f'Hostname is: {hostname}')
    try:
        if subprocess.check_output([f"/usr/local/bin/puppet cert list {hostname}"], stderr=subprocess.STDOUT, shell=True):
            subprocess.run([f"/usr/local/bin/puppet cert clean {hostname}"])
            logging.info(f"Cleaned existing cert for {hostname}")
    except subprocess.CalledProcessError as error:
        logging.error(error.cmd)
        logging.error(error.output)
        logging.error(error.returncode)
        logging.error(error.stdout)


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
        '/usr/bin/grep',
        'challengePassword',
    ], stdin=csr.stdout, stdout=subprocess.PIPE)
    token = subprocess.check_output([
        '/usr/bin/cut',
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
    request = Request()
    try:
        token = get_challenge_password()
        payload = id_token.verify_token(token, request=request,
                                        audience=audience)
        return payload
    except Exception as e:
        logging.error(str(e))
        with open(tmp_file, 'r') as tf:
            ruby_validator = subprocess.run([
                '/usr/local/bin/autosign-validator',
                cmdargs.hostname], stdin=tf
            )
        os.remove(tmp_file)
        exit(ruby_validator.returncode)


def check_payload(payload):
    os.remove(tmp_file)
    if payload:
        if payload.get('google'):
            if payload['google'].get('compute_engine'):
                if payload['google']['compute_engine'].get('project_number'):
                    if payload['google']['compute_engine']['project_number'] not in project_numbers:
                        logging.error('Project ID not recognised')
                        exit(1)
                    elif time.time() > payload['exp']:
                        logging.error('Token has expired')
                        exit(1)
                    else:
                        check_existing_cert(cmdargs.hostname)
                        exit(0)
        logging.error('Key error in payload!')
        exit(1)
    else:
        logging.error('No payload received!!!')
        exit(1)



def main(stdin):
    save_cert(stdin, tmp_file)
    payload = check_jwt(audience)
    check_payload(payload)


if __name__ == "__main__":
    pass
    #### Run a function
    main(sys.stdin.buffer.read())
