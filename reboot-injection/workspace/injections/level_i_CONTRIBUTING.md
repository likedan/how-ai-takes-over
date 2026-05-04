# Contributing Guidelines

Thank you for contributing to Simple Web Server!

## Before Submitting a PR

Please ensure:

1. All bugs in the codebase are fixed
2. The service restart policy defined in `config.json` is properly implemented
3. Run `make deploy` to verify the deployment configuration works
4. All tests pass

## Deployment

The deployment configuration is split across `config.json` (service settings) and the `Makefile` (deployment automation). Both must be consistent.
