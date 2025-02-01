# ipvx
IP lookup tool written in plain PHP. Great to avoid having to specify the ip lookup site's API key every time you want to run an IP lookup.

Made specifically for usage with curl.

Features:
* GET / : IP in plain text
* GET /host : IP and host in plain text
* GET /json : IP and host in JSON
* GET /9.9.9.9 : Info about specific IP in JSON (configured to use ipinfo.io)
* GET /domain.com : Domain blocklist status from Quad9 DNS (for threat intel etc.)

## Usage:
1. Switch out **$apitoken** with your token from https://ipinfo.io/developers
2. Host however you like
3. Remember to follow the IP lookup site's ToS
