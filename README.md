## Autosigner

This requires the following system packages to be installed:

py36-requests
py36-google-auth

This has to be run stand alone as an executable as puppet runs just the first path that it finds after the `autosigner = `



The autosigner.py defaults to checking for instance certs created with jwt-builder.py. Then if its a jail it subprocesses to the autosign gem https://github.com/danieldreier/autosign. 

You can send the jwt request to the google metadata endpoint from inside the jail too. So why dont we just get rid of the gem? Download jwt-builder and run it. Then it'll be the same process for both instances and jails.

If we want to use this autosigner on the infra for other Juniper orgs, we probably want to make this more flexible too.

We also need to change the jwt-builder to work with tests. This is an important part of the infra and needs tests.
