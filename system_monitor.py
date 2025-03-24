# This file will parse through SSH logs to identify and warn of possible 
# brute force attacks from the same IP within a short time period

from datetime import datetime, timedelta, timezone
import os
import subprocess
import threading
# from prettytable import PrettyTable
import time
import re
import requests
from flask import Flask, render_template, jsonify, redirect, url_for

app = Flask("__name__")

# define dictionary for failed attempts
failed_attempts = {}
alert_messages = {}
warning_messages = {}

# open ssh log file and begin reading through it
alert_counts = {"brute_force": 0, "successful_login": 0}

# this function will get the current datetime in iso format
def get_current_datetime():
    return datetime.now(timezone.utc);

# This function will extract the timestamp from the current line in a file
def extract_timestamp(line):
    # define regex pattern for datetime
    datetime_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[-+]\d{2}:\d{2}"
    match = re.search(datetime_pattern, line);
    datetime_str = match.group();
    dt = datetime.fromisoformat(datetime_str);
    return dt;

# this function will search for an IP address in the current line of a file
def extract_ip(line):
    # define regex pattern for ip
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    match = re.search(ip_pattern, line);
    ip = match.group();
    return ip;

# define function to get ip locations
def locate_ip(ip):
    response = requests.get(f'https://ipinfo.io/{ip}/json');
    if response.status_code == 200:
        data = response.json()
        location = f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}"
        return location;
    return "Location not found."

# create a route for chart data
@app.route("/chart_data")
def chart_data():
    return jsonify(alert_counts)

# parse through ssh logs
def parse_log():
    global alert_counts

    try:
        file = open("/var/log/auth.log", "r")
        file.seek(0, 2)
        
        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue
            
            if "Failed password for" in line:
                timestamp = extract_timestamp(line)
                ip = extract_ip(line)
                now = get_current_datetime()

                # create new entry for ip/key if not already in dictionary
                if ip not in failed_attempts:
                    failed_attempts[ip] = []
                    alert_messages[ip] = []
                    print(f"SSH attempt from new IP: {ip}")
                
                if (now - timestamp) <= timedelta(seconds=60):
                    failed_attempts[ip].append(timestamp)
                    
                    if len(failed_attempts[ip]) >= 3:
                        alert = f"🚨 BRUTE FORCE ATTACK DETECTED FROM: {ip} 🚨"
                        location = locate_ip(ip)
                        alert_message = {"alert": alert, "location": location}
                        alert_messages[ip].append(alert_message)

                        # Increment the count for brute force alerts
                        alert_counts["brute_force"] += 1
            
            if "Accepted password for" in line:
                ip = extract_ip(line)

                if ip not in warning_messages:
                    warning_messages[ip] = []

                message = f"Successful SSH Login from: {ip}"
                location = locate_ip(ip)
                warning = {"alert": message, "location": location}
                warning_messages[ip].append(warning)

                print(f"DEBUG: Warnings for {ip}: {warning_messages[ip]}")

                # Increment the count for successful login warnings
                alert_counts["successful_login"] += 1

    except FileNotFoundError:
        print("Unable to open /var/log/auth.log")


# function to monitor network connections in a table
def get_network_connections():

    while True: 
        # run 'ss -tun' as a subprocess
        result = subprocess.run(["ss", "-tun4"],stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # verify command ran 
        if result.returncode != 0:
            print("Error running ss command!")
            return
        
        output = result.stdout;
        lines = output.splitlines()

        connections = [];

        # iterate through lines starting after 1 (headers)
        for line in lines[1:]:
            parts = line.split();
            net_id = parts[0];
            state = parts[1];
            local_address = parts[4];
            peer_address = parts[5];
            # table.add_row([net_id, local_address, peer_address, state])
            connections.append([net_id, local_address, peer_address, state]);
        
        
        return connections
    
# create a function for clearing alerts and warnings in front end
@app.route("/clear_alerts", methods=["POST"])
def clear_alerts():
    global alert_messages, warning_messages
    
    alert_messages = {}
    warning_messages = {}

    return redirect(url_for("index"))


# create flask route for index page
@app.route("/")
def index():

    connections = get_network_connections();

    alerts = [];

    #  iterate through the attempts associated with each IP
    for alert_list in alert_messages.values():
        alerts.extend(alert_list)

    warnings = []
    
    # iterate through warning messages
    for warning_list in warning_messages.values():
        warnings.extend(warning_list);
            
    return render_template('index.html', connections=connections, alerts=alerts, warnings=warnings)

def main():
    print("Welcome to System Monitor")

    # Create threads for log parsing and network monitoring
    log_thread = threading.Thread(target=parse_log, daemon=True)

    # Start the threads
    log_thread.start()

    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == '__main__':
    main();