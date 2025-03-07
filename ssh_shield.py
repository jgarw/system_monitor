# This file will parse through SSH logs to identify and warn of possible 
# brute force attacks from the same IP within a short time period

import datetime
import re

def extract_timestamp(line):
    # extract the datetime from the file line
    datetime_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[-+]\d{2}:\d{2}"
    match = re.search(datetime_pattern, line);
    datetime_str = match.group();

    dt_obj = datetime.datetime.fromisoformat(datetime_str);
    print("Extracted Datetime Object:", dt_obj);

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