<?php
function sanitizeInput($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}

function validateIpAddress($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $reserved_ranges = [
            '10.0.0.0/8',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '172.16.0.0/12',
            '192.0.2.0/24',
            '192.88.99.0/24',
            '192.168.0.0/16',
            '198.18.0.0/15',
            '198.51.100.0/24',
            '203.0.113.0/24',
            '224.0.0.0/4',
            '240.0.0.0/4'
        ];

        foreach ($reserved_ranges as $range) {
            if (ip_in_range($ip, $range)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

function ip_in_range($ip, $range) {
    list($subnet, $mask) = explode('/', $range);
    return (ip2long($ip) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $address = sanitizeInput($_POST['address']);
    $port = sanitizeInput($_POST['port']);


    if (!is_numeric($port) || $port < 1 || $port > 65535) {
        die("端口号无效。");
    }


    if (filter_var($address, FILTER_VALIDATE_IP)) {
        $ip = $address;
    } else {
        $ip = gethostbyname($address);
        if ($ip == $address) {
            die("域名无效。");
        }
    }

    // Validate resolved IP address
    if (!validateIpAddress($ip)) {
        die("无效或私有IP地址。");
    }

    $connection = @fsockopen($ip, $port, $errno, $errstr, 5);

    if (is_resource($connection)) {
        echo "端口 $port 于 $address ($ip)  目前开启。";
        fclose($connection);
    } else {
        echo "端口 $port 于 $address ($ip)  目前关闭。 错误: $errstr ($errno)";
    }
} else {
    echo "无效请求。";
}
?>
