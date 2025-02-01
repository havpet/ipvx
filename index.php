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
    $ip_array = null; 

    $apitoken = ""; // Your ipinfo.io API token

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
        if($input == "json") {
            header('Content-Type: application/json; charset=utf-8');

            $ip_array = Array (
                "ip" => $ip,
                "hostname" => gethostbyaddr($ip)
            );

            echo json_encode($ip_array, JSON_PRETTY_PRINT);
        }

        // /x.x.x.x
        else if(filter_var($input, FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) || filter_var($input, FILTER_VALIDATE_IP,FILTER_FLAG_IPV6)) {
            header('Content-Type: application/json; charset=utf-8');

            $ip_details = json_decode(file_get_contents("https://ipinfo.io/{$input}/json?token=$apitoken"));

            $ip_array = Array (
                "ip" => $input,
                "hostname" => $ip_details->hostname,
                "city" => $ip_details->city,
                "region" => $ip_details->region,
                "country" => $ip_details->country,
                "org" => $ip_details->org
            );

            echo json_encode($ip_array, JSON_PRETTY_PRINT);
        }

        // ipvx.no/domain.no
        else if(isValidDomain($input)) {
            header('Content-Type: application/json; charset=utf-8');

            $domain_details = json_decode(file_get_contents("https://api.quad9.net/search/{$input}"));

            $domain_array = Array (
                "domain" => $input,
                "quad9Block" => $domain_details->blocked
            );

            echo json_encode($domain_array, JSON_PRETTY_PRINT);
        }

        else {
            header('Location: /');
        }
    }

    function isValidDomain($domain) {
        $domainPattern = "/^(?!:\/\/)([a-zA-Z0-9-_]{1,63}\.)+[a-zA-Z]{2,6}$/";
    
        return preg_match($domainPattern, $domain);
    }
    
?>