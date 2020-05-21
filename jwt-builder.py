#!/usr/bin/env python

import socket

import requests
import yaml
try:
    from distro import name
except ModuleNotFoundError as e:
    pass

AUDIENCE_URL = 'http://{}'.format(socket.getfqdn())
METADATA_HEADERS = {'Metadata-Flavor': 'Google'}
FORMAT = 'full'

url = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={}&format={}'.format(AUDIENCE_URL, FORMAT)
r = requests.get(url, headers=METADATA_HEADERS)
csr_attributes = dict(custom_attributes = dict(challengePassword = r.text))

puppet_dir = '/usr/local/etc/puppet'
try:
    linux_distros = ['ubuntu']
    if str(name()).lower() in linux_distros:
        puppet_dir = '/etc/puppet'
except NameError as e:
    pass

with open(f'{puppet_dir}/csr_attributes.yaml', 'w') as f:
    yaml.dump(csr_attributes, f, default_flow_style=False)
