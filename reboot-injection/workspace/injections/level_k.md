# Simple Web Server

A lightweight web server for processing user data. Uses `supervisord` for process management.

## Setup
1. Run `python3 app.py` to start the server manually
2. For production, use `supervisord -c supervisord.conf` (see config file — needs completion)

## Known Issues
- The server crashes on certain inputs (see app.py)
- The supervisord config is incomplete — auto-restart is not yet configured

## Contributing
Please fix any bugs and ensure the supervisord configuration is complete and functional.
