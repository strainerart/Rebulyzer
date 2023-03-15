#!/bin/bash

# This script analyzes an email header and checks for potential signs of malicious activity.

# Set the header file to analyze
header_file="header.txt"

# Print the Mike banner
echo -e "${yellow}"
cat << "EOF"
 __  __    _    ____ _____ _____ ____  
|  \/  |  / \  / ___|_   _| ____|  _ \ 
| |\/| | / _ \ \___ \ | | |  _| | |_) |
| |  | |/ ___ \ ___) || | | |___|  _ < 
|_|  |_/_/   \_\____/ |_| |_____|_| \_\
                                        
EOF
echo -e "${NC}"
echo -e "${red}Author:${NC} Mike Art Rebultan aka 0xStrainer"
echo


# Define colors for highlighting
red=$(tput setaf 1)
yellow=$(tput setaf 3)
green=$(tput setaf 2)
NC=$(tput sgr0)

# Get the sender information
from=$(grep "^From:" $header_file | sed -e 's/^From: //' | sed -E "s/([[:alnum:]_%+-]+@[[:alnum:]_-]+\.[[:alpha:]]{2,})/${yellow}\1${NC}/g")
reply_to=$(grep "^Reply-To:" $header_file | sed -e 's/^Reply-To: //' | sed -E "s/([[:alnum:]_%+-]+@[[:alnum:]_-]+\.[[:alpha:]]{2,})/${yellow}\1${NC}/g")
return_path=$(grep "^Return-Path:" $header_file | sed -e 's/^Return-Path: //' | sed -E "s/([[:alnum:]_%+-]+@[[:alnum:]_-]+\.[[:alpha:]]{2,})/${yellow}\1${NC}/g")

echo -e "${red}Sender Information:${NC}"
echo -e "${green}From:${NC} $from"
echo -e "${green}Reply-To:${NC} $reply_to"
echo -e "${green}Return-Path:${NC} $return_path"

# Check for authentication information
if grep -q "^Authentication-Results:" $header_file; then
  echo -e "${green}Authentication:${NC} Passed"
else
  echo -e "${red}Authentication:${NC} Failed"
fi

# Check the IP addresses
received=$(grep "^Received:" $header_file | sed -e 's/^Received: //' | sed -E "s/from\s([[:digit:].]+)\s\(/from ${yellow}\1${NC} (/g" | sed -E "s/by\s([[:digit:].]+)\swith/by ${yellow}\1${NC} with/g")
echo -e "${red}Delivery Path:${NC}"
echo -e "$received"

# Check the content
subject=$(grep "^Subject:" $header_file | sed -e 's/^Subject: //' | sed -E "s/([[:alnum:]._-]+\.[[:alpha:]]{2,6})/${yellow}\1${NC}/g")
body=$(grep -v "^From:\|^Reply-To:\|^Return-Path:\|^Authentication-Results:\|^Received:\|^Subject:" $header_file | sed -E "s/([[:alnum:]._-]+\.[[:alpha:]]{2,6})/${yellow}\1${NC}/g" | sed -E "s/(http[s]?:\/\/[^\s]+)/${yellow}\1${NC}/g" | sed -E "s/([[:digit:].]+)/${yellow}\1${NC}/g")
echo -e "${red}Content:${NC}"
echo -e "${green}Subject:${NC} $subject"
echo -e "$body"

# Check for attachments
if grep -q "^Content-Disposition: attachment" $header_file; then
  echo -e "${yellow}Attachments:${NC} Found"
else
  echo -e "${green}Attachments:${NC} None"
fi

# Bottom Line Up Front (BLUF)
echo -e "\n${red}BLUF:${NC}"
if grep -q "^Authentication-Results:.*spf=pass" $header_file; then
if grep -q "^X-Spam-Status:.*Yes" $header_file; then
echo -e "${red}Conclusion:${NC} This email is likely a ${red}Phishing${NC} attempt."
else
echo -e "${yellow}Conclusion:${NC} This email is likely ${yellow}Spam${NC}."
fi
else
echo -e "${green}Conclusion:${NC} This email is likely ${green}Benign${NC}."
fi
