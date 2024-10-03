A3N is a light-weight identyt and access management service for jwt based authentication.

# Set up
## Dependencies
Install mysql and set it up.

## Configuration
### Secrets
The following secrets must be provided as environment variables:
- "A3N_ENCRYPTION_KEY" for the key used to sign the jwts
- "A3N_DB_PASSWORD" for the database password
- "A3N_EMAIL_API_KEY" for the email service api key (atm only Sendgrid is supported)

### Config
The `config/config.json` file contains two objects:
- `api` to provide variables
- `branding` to provide customizations
```json
{
    "api": {
    },
    "branding": {
    }
}
```
#### Api Vars
Provide the following data inside the `api` object:
- MySql connection:
```json
"database": {
    "user": "root",
    "address": "192.108.1.1",
    "name": "auth"
},
```
- client domain for the email links and jwt subject:
```json
"client": {
    "domain": "http://myapp.com"
},
```
- jwt access token settings:
```json
"token": {
    "refreshExp": 10,
    "accessExp": 5
},
```
- email service vars (only Sendgrid is currently supported):
```json
"email": {
    "provider": "sendgrid",
    "sender": {
        "address": "no-reply@myapp.com",
        "name": "myapp"
    },
    "hardVerify": false
}
```

#### Branding
Use the `branding` object to provide custom colors for the emails and the web client:
```json
"colorScheme": {
    "primary": "#FADE84",
    "secondary": "#6F826F",
    "background": "#6F826F",
    "font": "#FFFFFF",
    "link": "#FADE84"
}
```
To use a custom logo, provide the url to the file. It must be a png file named 'logo.png', with dimentions 500px by 500px.
```json
"logoUrl": "https://github.com/agusespa/a3n/blob/main/config/assets/logo.png?raw=true"
```

## Install
`make install` will guide you through the setup process for provisioning the database.
Make sure you provide the variables in the config file and environment variables. See [Api Vars](#Api Vars).
Alternatively, you can use the schema file to set up the database and admin user manually.

## Build and run
`make build` generates binaries with linux amd64 as the default plataform.
To specify other platforms, specify the os and architecture: `make build GOOS=darwin GOARCH=arm64`
To start the server, execute the binary:
```sh
./dist/a3n-server
```
### Flags
`-dev` will start the server in development mode which enables debugging logs.
