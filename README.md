# ipvx
IP lookup tool in PHP with threat intelligence features.

Features:
* GET / : IP in plain text
* GET /host : IP and host in plain text
* GET /json : IP and host in JSON
* GET /9.9.9.9 : Info about specific IP in JSON (configured to use ipinfo.io and AbuseIPDB)

## Usage:
1. Switch out **$ipinfotoken** with your token from https://ipinfo.io/developers and **$abuseipdbtoken** with your token from https://abuseipdb.com/
2. Host however you like
3. Remember to follow the IP lookup site's ToS
