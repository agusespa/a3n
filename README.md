** Do NOT use -- Work in progress **

A3N is a fast and light-weight authentication microservice.

# Build
## Basic variables
Use the `config/api.json` file to customize api variables.

## Secrets
The following secrets must be provided as environment variables:
- "A3N_ENCRYPTION_KEY" for the key used to sign the jwts
- "A3N_DB_PASSWORD" for the database password
- "A3N_EMAIL_API_KEY" for the email service api key

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
    "domain": "http://localhost:3000"
},
```
- MySql connection:
```json
"database": {
    "user": "root",
    "address": "localhost:3306",
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
- email service vars (atm only sendgrid is supported):
```json
"email": {
    "provider": "sendgrid",
    "sender": {
        "address": "agustinespania@gmail.com",
        "name": "eCom"
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

---
# Development
## Git workflow
1. Use 'feature' branches for local development.
2. Push and merge into 'develop' branch.

### Branches
#### 'main'
Default and Protected.
Code that has been deployed to PROD and verified.
Only merge into 'main' from 'release' branches. 
#### 'develop'
Code that is ready to be deployed for testing to DEV and TEST environments. Not for local development.
##### 'feature/', 'bugfix/' and other branches
Name them so: '[type]/[issue-number]/[task-title]'
Remove after merging into 'develop' branch.

### Messages
To maintain an explicit commit history that makes it easy to cherrypick, please adhere to  the Conventional Commits Specification. The commit message should be structured as follows:
```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```
Most common types are:
- fix: patches a bug in your codebase (this correlates with PATCH in Semantic Versioning)
- feat: introduces a new feature to the codebase (this correlates with MINOR in Semantic Versioning)
- chore: changes to infrastructure, build processes, documentation, cleanup
- refactor
- build

### Custom Git Hooks
#### Setup
This repository contains custom hooks. To use them (only UNIX), add this to the .git/config file:
```
hooksPath = ./scripts/hooks
```
#### Options
If you need to skip the hook for a specific commit, you can use the `--no-verify` option:
```
git commit -m "message" --no-verify
```
#### Test
