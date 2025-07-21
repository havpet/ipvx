<?php
    session_start();
    include "functions.php";

    if(empty($_SERVER['HTTPS'])) {
        header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    }

    header("Access-Control-Allow-Methods: GET");
    header("Access-Control-Allow-Origin: *");
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains");

    $ip = $_SERVER['REMOTE_ADDR'];
    $input = $_GET['input'];

    $ipinfo_token = ""; // Your ipinfo.io API token
    $abuseipdb_token = ""; // Your abuseipdb.com token
    $threatfox_token = ""; // Your threatfox.abuse.ch token
    $ipdata_token = ""; // Your ipdata.co token

    $allowed_ip = in_array($_SERVER['REMOTE_ADDR'], ['0.0.0.0']); // Whitelisted IP's for the IP API calls

    // ip return
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

            echo json_encode(
                getIpInfo($input, $ipinfo_token, $abuseipdb_token, $ipdata_token), 
                JSON_PRETTY_PRINT
            );
        }

        // /domain.com
        else if($allowed_ip && validateDomainName($input)) {
            
            header('Content-Type: application/json; charset=utf-8');

            echo json_encode(
                getDomainInfo($input, $threatfox_token), 
                JSON_PRETTY_PRINT
            );
        }

        else {
            header('Location: /');
        }
    }
    
?>
