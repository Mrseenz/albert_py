<?php
// We can't just store the response as a static file because the serverKP in the response
// is based on the HandshakeRequestMessage in the request.
//
// To get around this, we'll store the response as a template and then replace the serverKP
// with the correct value.
//
// The serverKP is the HandshakeRequestMessage with the first byte XORed with 0x41.

function get_response_template_1() {
    return '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>serverKP</key>
    <data>__SERVER_KP_PLACEHOLDER__</data>
    <key>FDRBlob</key>
    <data>ukMtH9RdSQvHzBx7FiBGr7/KcmlxX/XwoWenWb6IRM=</data>
    <key>SUInfo</key>
    <data>HAEQTDM9LOEoZRBRuuU5SwnRZNiDx7K3zwMj7Zw3KPnfc5Q48eSSwNLNN8Isrlsk+Qs9SSbiDWkeMGwS4fa9nX6mf7qUDhH8bkHahyn0neXnkEcWfW2PXs79zAZyuQ1uMylDdaRTlUqemDLk1Bwm+yQhyj1+lIq1mb</data>
    <key>HandshakeResponseMessage</key>
    <data>AmKxRFuvy77iEmSdq7BvvvyKcQjZxNjj8hULEEs/VGSc2qN4Q+mfBJwIgOG+srIYMBMMfofZDi/x8kG9m4KCj3xj21fSRCTH94VnqZ12fXGcydoo1hKY+i5HKNI701hRlYA/+Tgvqeg3gcFaTfoRAK85I1qJ57CySHFXXfKil7gUJdae4Ay2mpsre0surDKSKSL5wuitQGvL40d1Dv1xre7xTHHT82bz0DSayD7JelbTjtsg8rmUEerO43JZ5mDKh8XuIoIEH8fnvci/lX7DHs7fx4iEjjFGWyfcSeBxtmKDgHBjhEoyUXM7eMpJQy5gTHX0rV/fRsc+7ZJFUUhUyK3qSKpvgEAztzxJ1mA60AR2flTFrCXn3aayHDmOVVTthsDr19wat2Cy2n+4cIcIqdS105GwngLh5HpLY5+UN+sl/ud7JkSpi3rSg+/ALRjEspGd66N9IMAMjVwqB7CJCJqPM7iLSM/erW6uOjZtKRL0zjGs1SDPyKUTWnv9wHXDFNMrcdB29hRMDtEGjNN7zouSX5/cERJNSjIl0CNmscnLVbpdUfqyNSVkjVA6UO0YucvdykDjnffJMsR8fnvoEryAAoAAQMABQAQQQJDBQtplviJJBclj5UOOpcpQ==</data>
</dict>
</plist>';
}

function get_response_template_2() {
    return '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>serverKP</key>
    <data>__SERVER_KP_PLACEHOLDER__</data>
    <key>FDRBlob</key>
    <data>ukMtH9RdSQvHzBx7FiBGr7/KcmlxX/XwoWenWb6IRM=</data>
    <key>SUInfo</key>
    <data>HAEV0M9LOEoZRBRuuU5SwnRZNiDx7K3zwMj7Zw3KPnfc5Q48eSSwNLNN8Isrlsk+Qs9SSbiDWkeMGwS4fa9nX6mf7qUDhH8bkHahyn0neXnkEcWfW2PXs79zAZyuQ1uMylDdaRTlUqemDLk1Bwm+yQhyj1+lIq1mb</data>
    <key>HandshakeResponseMessage</key>
    <data>AmKxRFuvy77iEmSdq7BvvvyKcQjZxNjj8hULEEs/VGSc2qN4Q+mfBJwIgOG+srIYMBMMfofZDi/x8kG9m4KCj3xj21fSRCTH94VnqZ12fXGcydoo1hKY+i5HKNI701hRlYA/+Tgvqeg3gcFaTfoRAK85I1qJ57CySHFXXfKil7gUJdae4Ay2mpsre0surDKSKSL5wuitQGvL40d1Dv1xre7xTHHT82bz0DSayD7JelbTjtsg8rmUEerO43JZ5mDKh8XuIoIEH8fnvci/lX7DHs7fx4iEjjFGWyfcSeBxtmKDgHBjhEoyUXM7eMpJQy5gTHX0rV/fRsc+7ZJFUUhUyK3qSKpvgEAztzxJ1mA60AR2flTFrCXn3aayHDmOVVTthsDr19wat2Cy2n+4cIcIqdS105GwngLh5HpLY5+UN+sl/ud7JkSpi3rSg+/ALRjEspGd66N9IMAMjVwqB7CJCJqPM7iLSM/erW6uOjZtKRL0zjGs1SDPyKUTWnv9wHXDFNMrcdB29hRMDtEGjNN7zouSX5/cERJNSjIl0CNmscnLVbpdUfqyNSVkjVA6UO0YucvdykDjnffJMsR8fnvoEryAAoAAQMABQAQQQJDBQtplviJJBclj5UOOpcpQ==</data>
</dict>
</plist>';
}

// All we have to do is get the request body, find the HandshakeRequestMessage,
// XOR the first byte with 0x41, and then replace the serverKP in the response
// template with the new value.
$request_body = file_get_contents('php://input');

// The request is a plist, so we can use a regex to find the HandshakeRequestMessage
$matches = [];
preg_match('/<key>HandshakeRequestMessage<\/key>\s*<data>(.*?)<\/data>/s', $request_body, $matches);
$handshake_request_message = base64_decode($matches[1]);

// XOR the first byte with 0x41
$handshake_request_message[0] = chr(ord($handshake_request_message[0]) ^ 0x41);

// The response depends on whether the request is for the first or second handshake
// We can differentiate them by the length of the CollectionBlob
$matches = [];
preg_match('/<key>CollectionBlob<\/key>\s*<data>(.*?)<\/data>/s', $request_body, $matches);
$collection_blob = $matches[1];

if (strlen($collection_blob) > 10000) {
    // First handshake
    $response = get_response_template_1();
    $content_type = 'application/json';
} else {
    // Second handshake
    $response = get_response_template_2();
    $content_type = 'application/xml';
}

// Replace the serverKP in the response template with the new value
$response = str_replace('__SERVER_KP_PLACEHOLDER__', base64_encode($handshake_request_message), $response);

// Send the response
header('Server: Apple');
header('Date: ' . gmdate('D, d M Y H:i:s T'));
header('Content-Type: ' . $content_type);
header('Transfer-Encoding: chunked');
header('Connection: close');
header('Cache-Control: no-cache, no-store, max-age=0, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
header('Strict-Transport-Security: max-age=31536000; includeSubdomains');
header('Referrer-Policy: no-referrer');
header('X-B3-TraceId: 32be1f0761158a18');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');

if ($content_type === 'application/json') {
    // Convert the XML response to a byte array in a JSON object
    $response_bytes = [];
    for ($i = 0; $i < strlen($response); $i++) {
        $response_bytes[] = ord($response[$i]);
    }
    echo json_encode($response_bytes);
} else {
    echo $response;
}
