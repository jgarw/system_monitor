# This file will parse through SSH logs to identify and warn of possible 
# brute force attacks from the same IP within a short time period

from datetime import datetime, timedelta, timezone
import time
import re

# define dictionary for failed attempts
failed_attempts = {}

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

# open ssh log file and begin reading through it
def parse_log():

    # open the auth.log file
    try:
        file = open("/var/log/auth.log", "r");

        file.seek(0, 2);
        # iterate through the file line by line
        while True:
                line = file.readline()

                # No new line, sleep for a second and try again
                if not line:
                    time.sleep(1)
                    continue
                
                # search for failed ssh password string
                if "Failed password for" in line:
                    
                    # extract the timestamp from the log line
                    timestamp = extract_timestamp(line);

                    # extract the ip from the log line
                    ip = extract_ip(line);

                    # get the current datetime
                    now = get_current_datetime();

                    # if there is not already a key entry for this ip, initialize one
                    if ip not in failed_attempts:
                        failed_attempts[ip] = [];
                        print(f"SSH attempt from new IP: {ip}")
                    
                    # check if the difference between timestamp and current time is < 60 seconds
                    if ((now - timestamp) <= timedelta(seconds=60)):
                        failed_attempts[ip].append(timestamp);

                        # if there are 3 or more failed attempts for this ip, trigger alert
                        if len(failed_attempts[ip]) >= 3:
                            print(f"🚨 BRUTE FORCE ATTACK DETECTED FROM: {ip} 🚨");

    # catch file not found exception
    except FileNotFoundError:
        print("Unable to open /var/log/auth.logs.");


def main():

    print("Welcome to System Monitor");

    # loop program indefinitely
    while True:
        parse_log();

if __name__ == '__main__':
    main();