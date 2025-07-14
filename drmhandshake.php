<?php
// We can't just store the response as a static file because the serverKP in the response
// is based on the HandshakeRequestMessage in the request.
//
// To get around this, we'll store the response as a template and then replace the serverKP
// with the correct value.
//
// The serverKP is the HandshakeRequestMessage with the first byte XORed with 0x41.

function get_response_template() {
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

// Replace the serverKP in the response template with the new value
$response = get_response_template();
$response = str_replace('__SERVER_KP_PLACEHOLDER__', base64_encode($handshake_request_message), $response);

// Send the response
header('Content-Type: application/xml');
echo $response;
