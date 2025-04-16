# ipvx
IP lookup tool written in plain PHP.

Made specifically for usage with curl.

Features:
* GET / : IP in plain text
* GET /host : IP and host in plain text
* GET /json : IP and host in JSON
* GET /9.9.9.9 : Info about specific IP in JSON (configured to use ipinfo.io)
* GET /domain.com : Domain blocklist status from Quad9 DNS (for threat intel etc.)

## Usage:
1. Switch out **$apitoken** with your token from https://ipinfo.io/developers or similar ip lookup website
2. Host however you like
3. Remember to follow the IP lookup site's ToS
