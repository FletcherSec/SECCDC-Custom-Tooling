#!/bin/bash

LOG_FILE="/var/log/auth.log"

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file does not exist: $LOG_FILE"
    exit 1
fi

awk '
BEGIN {
    FS="[ :]";
    OFMT = "%.0f";
}

function print_record(ip, user, most_recent, failures, successes) {
    print "Source IP:", ip;
    print "Username:", user;
    print "Most Recent Attempt:", most_recent;
    print "Total Failures:", failures;
    print "Total Successes:", successes;
    print ""; # Empty line for readability
}

# Function to convert month to a number
function month_to_num(month,    i, month_abbr, months) {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", month_abbr)
    for (i=1; i<=12; i++) {
        months[month_abbr[i]] = i
    }
    return months[month]
}

# Main processing
{
    # Extract the date, user, and IP
    month_num = month_to_num($1);
    date_stamp = sprintf("%04d%02d%02d%02d%02d%02d", $3, month_num, $2, $4, $5, $6);
    
    if ($0 ~ /Failed password/ || $0 ~ /authentication failure/) {
        split($0, info, " ");
        for (i = 1; i <= length(info); i++) {
            if (info[i] == "from") {
                ip = info[i+1];
                user = info[i-1];
                if (info[i-2] == "invalid") {
                    user = "invalid_user";
                }
            }
        }
        attempts[ip, user]++;
        failures[ip, user]++;
        recent_attempt[ip, user] = date_stamp;
    }
    
    if ($0 ~ /Accepted password/) {
        split($0, info, " ");
        for (i = 1; i <= length(info); i++) {
            if (info[i] == "from") {
                ip = info[i+1];
                user = info[i-1];
            }
        }
        attempts[ip, user]++;
        successes[ip, user]++;
        recent_attempt[ip, user] = date_stamp;
    }
}

# End of processing
END {
    for (key in attempts) {
        split(key, keys, SUBSEP);
        ip = keys[1];
        user = keys[2];
        print_record(ip, user, recent_attempt[ip, user], failures[ip, user], successes[ip, user]);
    }
}
' $LOG_FILE | sort -k5,5r -k9,9nr
