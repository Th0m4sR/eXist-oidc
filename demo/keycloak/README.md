# keycloak

This directory contains the files required to build the keycloak container for the demo.

The entrypoint that is added imports the existing realm config on startup and creates the two users for the demo.

To access the admin UI of Keycloak, you can log in under `http://localhost:8556` using

```Raw
admin
password
```

The created demo users that are created on startup are given in the README file of the demo directory.