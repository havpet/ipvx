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

    return Array (
        "ip" => $input,
        "hostname" => $ip_details->hostname,
        "city" => $ip_details->city,
        "region" => $ip_details->region,
        "country" => $ip_details->country,
        "org" => $ip_details->org,
        "domain" => $abuse_ip_details->data->domain,
        "domain_info" => "https://<your_domain>.com/{$abuse_ip_details->data->domain}",  
        "malicious%" => max($abuse_ip_details->data->abuseConfidenceScore, $threatfox_info->data[0]->confidence_level),
        "threat_info" => [
            "abuseipdb_confidence" => $abuse_ip_details->data->abuseConfidenceScore,
            "abuseipdb_reports" => $abuse_ip_details->data->totalReports,
            "abuseipdb_info" => "https://www.abuseipdb.com/check/{$input}",
            "threatfox_confidence" => $threatfox_info->data[0]->confidence_level,
            "threatfox_type" => $threatfox_info->data[0]->threat_type,
            "threatfox_malware" => $threatfox_info->data[0]->malware,
            "threatfox_link" => $threatfox_info->data[0]->id ? "https://threatfox.abuse.ch/ioc/{$threatfox_info->data[0]->id}/" : null
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
        "quad9" => $quad9_info->blocked,
        "threatfox_type" => $threatfox_info->data[0]->threat_type,
        "threatfox_malware" => $threatfox_info->data[0]->malware,
        "threatfox_confidence" => $threatfox_info->data[0]->confidence_level,
        "threatfox_link" => $threatfox_info->data[0]->id ? "https://threatfox.abuse.ch/ioc/{$threatfox_info->data[0]->id}/" : null
    );

}

function validateDomainName($domain) {

    $pattern = '/^(http[s]?\:\/\/)?(?!\-)(?:[a-zA-Z\d\-]{0,62}[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z\d]{1,63}$/';
    return preg_match($pattern, $domain);
}

?>
