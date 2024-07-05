** Do NOT use -- Work in progress **

A3N is a fast and light-weight microservice for basic jwt based authentication of front-end clients.

# Running the server
```sh
make run-dev # start the server with debugging enabled
```
## Secrets
The following secrets must be provided as environment variables:
- "A3N_ENCRYPTION_KEY" for the key used to sign the jwts
- "A3N_DB_PASSWORD" for the database password
- "A3N_EMAIL_API_KEY" for the email service api key (atm only Sendgrid is supported)

## Config
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
### Api Vars
Provide the following data inside the `api` object:
- client domain for the email links and jwt subject:
```json
"client": {
    "domain": "http://myapp.com"
},
```
- MySql connection:
```json
"database": {
    "user": "root",
    "address": "192.108.1.1",
    "name": "auth"
},
```
- jwt access token settings:
```json
"token": {
    "refreshExp": 10,
    "accessExp": 5
},
```
- email service vars (atm only Sendgrid is supported):
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

### Branding
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

# Building the server
```sh
make build
```
