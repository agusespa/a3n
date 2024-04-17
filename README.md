** Do NOT use -- Work in progress **

A3N is a fast and light-weight authentication microservice.

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
