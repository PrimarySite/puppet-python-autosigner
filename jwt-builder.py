#!/usr/bin/env python

import requests
import socket
import yaml

AUDIENCE_URL = 'http://{}'.format(socket.getfqdn())
METADATA_HEADERS = {'Metadata-Flavor': 'Google'}
FORMAT = 'full'

url = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={}&format={}'.format(AUDIENCE_URL, FORMAT)
r = requests.get(url, headers=METADATA_HEADERS)
csr_attributes = dict(custom_attributes = dict(challengePassword = r.text))

with open('/usr/local/etc/puppet/csr_attributes.yaml', 'w') as f:
    yaml.dump(csr_attributes, f, default_flow_style=False)

