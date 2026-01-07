# ipvx
![GitHub release (latest by date)](https://img.shields.io/github/v/release/havpet/ipvx?style=flat-square)

Quick and simple IP and domain threat intel using multiple data providers.

## Features
### GET / : IP in plain text
Returns the current IP of the visitor in plain text. This is the default page.

### GET /host : IP and host in plain text
Returns the current IP and hostname of the visitor in plain text for usage in command line tools or similar.

### GET /json : IP and host in JSON
Returns the current IP and hostname of the visitor in JSON format for programmatic usage.

### GET /0.0.0.0 : Info about specific IP in JSON
Returns info about the specified IP in JSON format. Sources: 
* Basic IP info from https://ipinfo.io/
* Abuse (spam, bruteforce etc) data from https://abuseipdb.com
* Blocklist info and security context of IP from https://ipdata.co

### GET /domain.com : Info about domain in JSON
Returns threat data related to specified domain name. Sources:
* Checks the https://quad9.net/ blocklist
* Malware related data from https://threatfox.abuse.ch/

## Usage
1. Obtain tokens from IPinfo (https://ipinfo.io/signup), AbuseIPDB (https://www.abuseipdb.com/register), Threatfox (https://auth.abuse.ch/) and ipdata.co (https://ipdata.co).
2. Add the tokens to the variables in index.php lines 16-19
3. Add the allowed source IP addresses to the $allowed_ip variable on line 21 to prevent breach of ToS.
3. Host on any PHP server.
