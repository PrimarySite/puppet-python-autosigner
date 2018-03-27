#!/usr/bin/env python

import os
import sys
import time
import argparse
import subprocess
import google.auth.transport.requests

from google.oauth2 import id_token
from .local import project_numbers


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
    with open(tmp_file, 'w') as w:
        w.write('{}'.format(stdin))


def get_challenge_password(tmp_file):

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
    password = subprocess.Popen([
        'cut',
        '-f2-',
        '-d\\:'
    ], stdin=cp_line.stdout).communicate()

    # Clean up the temp file as we don't want the OS drive filling
    # up with these files and also we don't want to leave challenge
    # passwords littering the /tmp directory
    os.remove(tmp_file)
    return password


def check_jwt(audience, token):
    # This function checks the validity of the token and audience and returns a
    # dictionary
    request = google.auth.transport.requests.Request()
    try:
        payload = id_token.verify_token(token, request=request, audience=audience)
    except ValueError:
        # This is catching all errors including expiries, which we don't want to do
        # but I'm not sure how to handle expired certs differently

        # To make this the default autosigner but to fall back to the ruby
        # autosigner gem if the token verification step above fails we
        # subprocess at this point and run the ruby autosigner as if we'd never
        # run the check with the fqdn as a cmdline arg and the cert a stdin redirect
        with open(tmp_file, 'r') as tf:
            subprocess.Popen([
                '/usr/local/bin/autosign',
                cmdargs.hostname], stdin=tf
            ).communicate()
        # We don't want the puppet master to sign the certificate because of this
        # autosigner so we exit 1 here.  The above autosigner may have signed this
        # already if it's a jail with a valid token.
        exit(1)
    # We need to return the payload here if we got through the try/except for use
    # in the payload checking function below
    return payload


def check_payload(payload):
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
    token = get_challenge_password(tmp_file)
    payload = check_jwt(audience, token)
    check_payload(payload)


if __name__ == "__main__":
    pass
    #### Run a function
    main(sys.stdin.buffer.read())
