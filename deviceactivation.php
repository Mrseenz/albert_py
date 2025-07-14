<?php
// The device activation endpoint is a bit more complicated than the handshake endpoint.
// It's a multipart form data request with two parts: "activation-info" and "InStoreActivation".
//
// The "activation-info" part is a plist that contains all the device information.
// The "InStoreActivation" part is a boolean that is always false.
//
// The response is an HTML page that contains a plist with the activation record.
//
// If the request contains the "login" and "password" fields, then it's the second
// request in the activation process. In this case, the response is a simple HTML
// page with a plist that tells the device that the activation was successful.
//
// If the request does not contain the "login" and "password" fields, then it's the
// first request in the activation process. In this case, the response is an HTML
// page with a form that asks for the user's Apple ID and password.

function get_response_template_1() {
    return '<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<meta name="keywords" content="iTunes Store" />
		<meta name="description" content="iTunes Store" />
		<title>iPhone Activation</title>
		<link href="https://static.deviceservices.apple.com/deviceservices/stylesheets/auth_styles.css" charset="utf-8" rel="stylesheet" />
		<script src = "https://static.deviceservices.apple.com/deviceservices/scripts/spinner_reload.js"></script>
		<script>
			var protocolElement = document.getElementById("protocol");
			var protocolContent = protocolElement.innerText;
			iTunes.addProtocol(protocolContent);
		</script>
		<style>.spinner { background-image: url("https://static.deviceservices.apple.com/deviceservices/images/spinner_reload_16px.png"); }</style>
	</head>
	<body >
		<div class="page">
			<div class="content">
				<section class="headline">
					<h1 class="title">
							<span class="title-text">Activation Lock</span>
					</h1>
					<div id="owner-message" class="message">
						<div id="message-title" class="message-title"></div>
						<p id="message-text" class="message-text"></p>
					</div>
					<p class="subtitle">This iPhone is linked to an Apple ID. Enter the Apple ID and password that were used to set up this iPhone."m•••••@gmail.com"</p>
						<label>
							<a tabindex="-1" target="_blank" class="activationhelp" href="https://support.apple.com/kb/TS4515">Activation Lock Help</a>
						</label>
				</section>
					<form method="post" id="auth_form" action="https://albert.apple.com/deviceservices/deviceActivation">
						<section class="sectioned-content">
							<label>
								Apple ID
								<input type="text" name="login" value="" placeholder="" spellcheck="false"/>
							</label>
							<label>
								Password<a tabindex="-1" target="_blank" class="forgot" href="https://iforgot.apple.com">Forgot?</a>
								<input type="password" name="password" />
							</label>
						</section>
						<input type="hidden" name="activation-info-base64" value="__ACTIVATION_INFO_PLACEHOLDER__" />
						<input type="hidden" name="isAuthRequired" value="true" />
						<section>
							<button id="btn-continue" class="btn-continue" type="submit" onclick="submitActivate();">Continue</button>
							<div id="submitted-spinner" class="spinner" style="display:none;"></div>
						</section>
					</form>
			</div>
				<img class="product-image" src="https://static.deviceservices.apple.com/deviceservices/images/iphone-7-jetblack.png"/>
		</div>
	</body>
</html>';
}

function get_response_template_2() {
    return '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html xmlns="http://www.apple.com/itms/" lang="en">
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<meta name="keywords" content="iTunes Store" />
		<meta name="description" content="iTunes Store" />
		<title>iPhone Activation</title>
		<link href="https://static.deviceservices.apple.com//deviceservices/stylesheets/common-min.css" charset="utf-8" rel="stylesheet" />
		<link href="https://static.deviceservices.apple.com//deviceservices/stylesheets/styles.css" charset="utf-8" rel="stylesheet" />
		<link href="https://static.deviceservices.apple.com//deviceservices/stylesheets/IPAJingleEndPointErrorPage-min.css" charset="utf-8" rel="stylesheet" />
		<script id="protocol" type="text/x-apple-plist">
			<plist version="1.0">
			  <dict>
			    <key>iphone-activation</key>
			    <dict>
			      <key>ack-received</key>
			      <true/>
			      <key>show-settings</key>
			      <true/>
			    </dict>
			  </dict>
			</plist>
		</script>
		<script>var protocolElement = document.getElementById("protocol");var protocolContent = protocolElement.innerText;iTunes.addProtocol(protocolContent);</script>
	</head>
	<body>
	</body>
</html>';
}

// Check if the request is the first or second step
if (isset($_POST['login']) && isset($_POST['password'])) {
    // Second step
    $response = get_response_template_2();
    header('Content-Type: text/html');
    echo $response;
} else {
    // First step
    // We need to get the activation-info from the request and put it in the response
    $matches = [];
    preg_match('/name="activation-info"\s*?\n(.*?)\n/s', file_get_contents('php://input'), $matches);
    $activation_info = $matches[1];

    $response = get_response_template_1();
    $response = str_replace('__ACTIVATION_INFO_PLACEHOLDER__', base64_encode($activation_info), $response);
    header('Content-Type: text/html');
    echo $response;
}
