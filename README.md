# System Monitor

System Monitor is a Python-based security tool designed to help detect potential brute force attacks on SSH authentication logs. This project was created as a self-learning exercise to explore Python, system monitoring, and cybersecurity concepts.

## Features
- Monitors `/var/log/auth.log` for failed SSH login attempts.
- Detects brute force attempts by identifying multiple failed logins from the same IP within a short time window.
- Alerts the user when a possible attack is detected.
- Runs continuously and updates in real-time as new log entries appear.

## Future Plans
- Implement an `ss`-based live connection table to display active TCP/UDP connections.
- Enhance logging and alerting mechanisms.
- Support additional system monitoring features.

## License
This project is open-source and available under the MIT License.