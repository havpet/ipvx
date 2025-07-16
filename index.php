<?php
    session_start();

    if(empty($_SERVER['HTTPS'])) {
        header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    }

    header("Access-Control-Allow-Methods: GET");
    header("Access-Control-Allow-Origin: *");
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains");

    $ip = $_SERVER['REMOTE_ADDR'];
    $input = $_GET['input'];

    $ipinfotoken = ""; // Your ipinfo.io API token
    $abuseipdbtoken = ""; // Your abuseipdb token

    $allowed_ip = in_array($_SERVER['REMOTE_ADDR'], ['0.0.0.0']); // Whitelisted IP's for the IP API calls

    // standard ip return
    if (!isset($input) || $input == "index.php") {
        header('Content-Type: text/plain;');
        echo $ip;
    }

    else {
        // /host
        if($input == "host") {
            header('Content-Type: text/plain;');
            echo $ip . ' | ' . gethostbyaddr($ip);
        }

        // /json
        else if($input == "json") {
            header('Content-Type: application/json; charset=utf-8');

            $ip_array = Array (
                "ip" => $ip,
                "hostname" => gethostbyaddr($ip)
            );

            echo json_encode($ip_array, JSON_PRETTY_PRINT);
        }

        // /x.x.x.x
        else if($allowed_ip && filter_var($input, FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) || filter_var($input, FILTER_VALIDATE_IP,FILTER_FLAG_IPV6)) {
            header('Content-Type: application/json; charset=utf-8');

            $ip_details = json_decode(file_get_contents("https://ipinfo.io/{$input}/json?token={$ipinfotoken}"));
            
            $abuse_ip_details = json_decode(file_get_contents(
                "https://api.abuseipdb.com/api/v2/check?ipAddress={$input}",
                false,
                stream_context_create([
                    'http' => [
                        'method' => 'GET',
                        'header' => "Key: {$abuseipdbtoken}"
                    ]
                ])
            ));

            $ip_array = Array (
                "ip" => $input,
                "hostname" => $ip_details->hostname,
                "city" => $ip_details->city,
                "region" => $ip_details->region,
                "country" => $ip_details->country,
                "org" => $ip_details->org,
                "domain" => $abuse_ip_details->data->domain,
                "abuse_confidence" => $abuse_ip_details->data->abuseConfidenceScore,
                "num_abuse_reports" => $abuse_ip_details->data->totalReports,
                "abuse_info" => "https://www.abuseipdb.com/check/{$input}"
            );

            echo json_encode($ip_array, JSON_PRETTY_PRINT);
        }

        else {
            header('Location: /');
        }
    }
    
?>
