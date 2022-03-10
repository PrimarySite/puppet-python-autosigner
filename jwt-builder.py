#!/usr/bin/env python3

# Standard Library
import socket

# 3rd-party
import httpx
import yaml

try:
    # 3rd-party
    from distro import name
except ModuleNotFoundError:
    pass

AUDIENCE_URL = f"http://{socket.getfqdn()}"
METADATA_HEADERS = {"Metadata-Flavor": "Google"}
URL = f"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={AUDIENCE_URL}&format=full&licenses=TRUE"


def query_google_jwt():
    with httpx.Client() as client:
        response = client.get(URL, headers=METADATA_HEADERS)

    jwt_response = dict(custom_attributes=dict(challengePassword=response.text))

    return jwt_response


def get_os_etc():
    # FreeBSD default
    os_etc = "/usr/local/etc/puppet"

    # Ubuntu
    try:
        linux_distros = ["ubuntu"]
        if str(name()).lower() in linux_distros:
            os_etc = "/etc/puppetlabs/puppet"
    except NameError:
        pass

    return os_etc


def dump_jwt_to_file(jwt_response, os_etc):
    with open(f"{os_etc}/csr_attributes.yaml", "w") as csr_attributes_file:
        yaml.dump(jwt_response, csr_attributes_file, default_flow_style=False)


def jwt_builder():
    jwt_response = query_google_jwt()
    os_etc = get_os_etc()
    dump_jwt_to_file(jwt_response, os_etc)


if __name__ == "__main__":
    jwt_builder()
