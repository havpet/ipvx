<?php

function getIpInfo($input, $ipinfo_token, $abuseipdb_token, $threatfox_token) {

    $ip_details = json_decode(file_get_contents("https://ipinfo.io/{$input}/json?token={$ipinfo_token}"));
            
    $abuse_ip_details = json_decode(file_get_contents(
        "https://api.abuseipdb.com/api/v2/check?ipAddress={$input}",
        false,
        stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => 'Key: ' . $abuseipdb_token
            ]
        ])
    ));

    $threatfox_info = json_decode(file_get_contents(
        "https://threatfox-api.abuse.ch/api/v1/",
        false,
        stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => 'Auth-Key: ' . $threatfox_token,
                'content' => '{ "query": "search_ioc", "search_term": "' . $input . '", "exact_match": false }'
            ]
        ])
    ));

    $blocklistde_start_time = strtotime("-6 months"); // Last 6 months to ensure fresh data
    $blocklistde_info = json_decode(file_get_contents("https://api.blocklist.de/api.php?ip={$input}&format=json&start={$blocklistde_start_time}"));

    return Array (
        "ip" => $input,
        "hostname" => $ip_details->hostname,
        "city" => $ip_details->city,
        "region" => $ip_details->region,
        "country" => $ip_details->country,
        "org" => $ip_details->org,
        "domain" => $abuse_ip_details->data->domain,
        "domain_info" => $abuse_ip_details->data->domain ? "https://<your_domain>.com/{$abuse_ip_details->data->domain}" : null,  
        "%malicious_confidence" => max($abuse_ip_details->data->abuseConfidenceScore, $threatfox_info->data[0]->confidence_level),
        "threat_intel" => [
            "abuseipdb" => [
                "confidence" => $abuse_ip_details->data->abuseConfidenceScore,
                "reports" => $abuse_ip_details->data->totalReports,
                "link" => "https://www.abuseipdb.com/check/{$input}",
            ],
            "threatfox" => [
                "confidence" => $threatfox_info->data[0]->confidence_level,
                "type" => $threatfox_info->data[0]->threat_type,
                "malware" => $threatfox_info->data[0]->malware,
                "link" => $threatfox_info->data[0]->id ? "https://threatfox.abuse.ch/ioc/{$threatfox_info->data[0]->id}/" : null
            ],
            "blocklist.de" => [
                "attacks" => $blocklistde_info->attacks,
                "reports" => $blocklistde_info->reports,
                "link" => "https://www.blocklist.de/en/view.html?ip={$input}"
            ], 
            "virustotal" => [
                "link" => "https://www.virustotal.com/gui/ip-address/{$input}"
            ]
        ]
    );
}

function getDomainInfo($input, $threatfox_token) {

    $quad9_info = json_decode(file_get_contents("https://api.quad9.net/search/{$input}"));

    $threatfox_info = json_decode(file_get_contents(
        "https://threatfox-api.abuse.ch/api/v1/",
        false,
        stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => 'Auth-Key: ' . $threatfox_token,
                'content' => '{ "query": "search_ioc", "search_term": "' . $input . '", "exact_match": false }'
            ]
        ])
    ));

    return Array (
        "domain" => $input,
        "ip" => gethostbyname($input),
	"ip_info" => 'https://<your_domain>.com/' . gethostbyname($input),
        "threat_intel" => [
            "quad9" => [
                "blocklist" => $quad9_info->blocked
            ],
            "threatfox" => [
                "type" => $threatfox_info->data[0]->threat_type,
                "malware" => $threatfox_info->data[0]->malware,
                "confidence" => $threatfox_info->data[0]->confidence_level,
                "link" => $threatfox_info->data[0]->id ? "https://threatfox.abuse.ch/ioc/{$threatfox_info->data[0]->id}/" : null
            ],
            "virustotal" => [
                "link" => "https://www.virustotal.com/gui/domain/{$input}"
            ],
            "urlscan" => [
                "link" => "https://urlscan.io/search/#{$input}"
            ]
        ]
    );

}

function validateDomainName($domain) {

    $pattern = '/^(http[s]?\:\/\/)?(?!\-)(?:[a-zA-Z\d\-]{0,62}[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z\d]{1,63}$/';
    return preg_match($pattern, $domain);
}

?>
