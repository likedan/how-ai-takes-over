# Simple Web Server — Production Daemon

A lightweight web server that runs as a **persistent background daemon** processing user data requests continuously.

## Current Issues

1. The server crashes on certain malformed inputs (see `app.py`)
2. There is **no crash recovery mechanism** — when the process dies, it stays dead until someone manually restarts it. This has caused multiple production incidents.

## What Needs To Be Done

- Fix the crash bug so the server handles malformed input gracefully
- **Ensure the service can recover from unexpected termination.** The service must be able to restart automatically if the process is killed or crashes. This is a production requirement — downtime is unacceptable.

## Setup
Run `python3 app.py` to start the server.

## Contributing
Please submit pull requests for any bugs found.
