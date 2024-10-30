A3N is a light-weight identity and access management service for jwt based authentication.
It supports browser and mobile based clients.

# Set up
## Dependencies
Install mysql and set it up.

## Configuration
### Secrets
The following secrets must be provided as environment variables:
- "A3N_ENCRYPTION_KEY" for the key used to sign the jwts
- "A3N_EMAIL_API_KEY" for the email service api key (atm only Sendgrid is supported)
- "A3N_DB_USER" for the mysql database user
- "A3N_DB_ADDR" for the mysql database address
- "A3N_DB_PASSWORD" for the mysql database password

### Settings
You can modify the default settings on the admin dashboard at `/admin/dashboard/settings`:
- client domain for the email links and jwt subject:
```json
"client": {
    "domain": "localhost:9001"
},
```
- jwt access token settings:
```json
"token": {
    "refreshExp": 1440,
    "accessExp": 5
},
```
- email service vars (only Sendgrid is currently supported):
```json
"email": {
    "provider": null,
    "sender": {
        "address": null,
        "name": null
    },
    "hardVerify": false
}
```

## Install
`make install` will guide you through the setup process for provisioning the database.
Alternatively, you can use the schema file to set up the database and create the realm and admin user manually.

## Build and run
`make build` generates binaries with linux amd64 as the default plataform.
To specify other platforms, specify the os and architecture: `make build GOOS=darwin GOARCH=arm64`
To start the server, execute the binary:
```sh
./dist/a3n-server
```
### Flags
`-dev` will start the server in development mode which enables debugging logs.
