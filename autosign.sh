#! /bin/sh

# Wrapper script to source the venv for the autosigner and then run it. Disregards the stdin given by the puppetserver because bash is being awkward about handling multiline stdin. Just cats the csr file instead.

cd /etc/puppetlabs/puppet-python-autosigner
export PATH="/etc/puppetlabs/puppet-python-autosigner/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/opt/puppetlabs/bin"
cat /etc/puppetlabs/puppetserver/ca/requests/$1.pem | python3 /etc/puppetlabs/puppet-python-autosigner/autosigner.py $1
