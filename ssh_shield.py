# This file will parse through SSH logs to identify and warn of possible 
# brute force attacks from the same IP within a short time period

import datetime
import re

# This function will extract the timestamp from the current line in a file
def extract_timestamp(line):

    # define regex pattern for datetime
    datetime_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[-+]\d{2}:\d{2}"
    match = re.search(datetime_pattern, line);
    datetime_str = match.group();

    dt = datetime.datetime.fromisoformat(datetime_str);
    
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

    now = datetime.datetime.now

    # open the auth.log file
    try:
        file = open("/var/log/auth.log", "r");
        # iterate through the file seaching for failed password string
        for line in file:
            if "Failed password for" in line:
                
                # extract the timestamp from the log line
                extract_timestamp(line);
                extract_ip(line);
                
                # print(line);
        print(line);
    # catch file not found exception
    except FileNotFoundError:
        print("Unable to open /var/log/auth.logs.");


def main():
    print("Welcome to BruteShield!");

    parse_log();

if __name__ == '__main__':
    main();