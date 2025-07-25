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
    return '<!DOCTYPE html>
<html>
   <head>
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
      <meta name="keywords" content="iTunes Store" />
      <meta name="description" content="iTunes Store" />
      <title>iPhone Activation</title>
      <link href="https://static.deviceservices.apple.com/deviceservices/stylesheets/common-min.css" charset="utf-8" rel="stylesheet" />
      <link href="https://static.deviceservices.apple.com/deviceservices/stylesheets/styles.css" charset="utf-8" rel="stylesheet" />
      <link href="https://static.deviceservices.apple.com/deviceservices/stylesheets/IPAJingleEndPointErrorPage-min.css" charset="utf-8" rel="stylesheet" />
      <script id="protocol" type="text/x-apple-plist"><plist version="1.0"><dict><key>ActivationRecord</key><dict><key>unbrick</key><true/><key>AccountTokenCertificate</key><data>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lCQWpBTkJna3Foa2lHOXcwQkFRVUZBREI1TVFzd0NRWURWUVFHRXdKVlV6RVQKTUJFR0ExVUVDaE1LUVhCd2JHVWdTVzVqTGpFbU1DUUdBMVVFQ3hNZFFYQndiR1VnUTJWeWRHbG1hV05oZEdsdgpiaUJCZFhSb2IzSnBkSGt4TFRBckJnTlZCQU1USkVGd2NHeGxJR2xRYUc5dVpTQkRaWEowYVdacFkyRjBhVzl1CklFRjFkR2h2Y21sMGVUQWVGdzB3TnpBME1UWXlNalUxTURKYUZ3MHhOREEwTVRZeU1qVTFNREphTUZzeEN6QUoKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFLRXdwQmNIQnNaU0JKYm1NdU1SVXdFd1lEVlFRTEV3eEJjSEJzWlNCcApVR2h2Ym1VeElEQWVCZ05WQkFNVEYwRndjR3hsSUdsUWFHOXVaU0JCWTNScGRtRjBhVzl1TUlHZk1BMEdDU3FHClNJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRREZBWHpSSW1Bcm1vaUhmYlMyb1BjcUFmYkV2MGQxams3R2JuWDcKKzRZVWx5SWZwcnpCVmRsbXoySkhZdjErMDRJekp0TDdjTDk3VUk3ZmswaTBPTVkwYWw4YStKUFFhNFVnNjExVApicUV0K25qQW1Ba2dlM0hYV0RCZEFYRDlNaGtDN1QvOW83N3pPUTFvbGk0Y1VkemxuWVdmem1XMFBkdU94dXZlCkFlWVk0d0lEQVFBQm80R2JNSUdZTUE0R0ExVWREd0VCL3dRRUF3SUhnREFNQmdOVkhSTUJBZjhFQWpBQU1CMEcKQTFVZERnUVdCQlNob05MK3Q3UnovcHNVYXEvTlBYTlBIKy9XbERBZkJnTlZIU01FR0RBV2dCVG5OQ291SXQ0NQpZR3UwbE01M2cyRXZNYUI4TlRBNEJnTlZIUjhFTVRBdk1DMmdLNkFwaGlkb2RIUndPaTh2ZDNkM0xtRndjR3hsCkxtTnZiUzloY0hCc1pXTmhMMmx3YUc5dVpTNWpjbXd3RFFZSktvWklodmNOQVFFRkJRQURnZ0VCQUY5cW1yVU4KZEErRlJPWUdQN3BXY1lUQUsrcEx5T2Y5ek9hRTdhZVZJODg1VjhZL0JLSGhsd0FvK3pFa2lPVTNGYkVQQ1M5Vgp0UzE4WkJjd0QvK2Q1WlFUTUZrbmhjVUp3ZFBxcWpubTlMcVRmSC94NHB3OE9OSFJEenhIZHA5NmdPVjNBNCs4CmFia29BU2ZjWXF2SVJ5cFhuYnVyM2JSUmhUekFzNFZJTFM2alR5Rll5bVplU2V3dEJ1Ym1taWdvMWtDUWlaR2MKNzZjNWZlREF5SGIyYnpFcXR2eDNXcHJsanRTNDZRVDVDUjZZZWxpblpuaW8zMmpBelJZVHh0UzZyM0pzdlpEaQpKMDcrRUhjbWZHZHB4d2dPKzdidFcxcEZhcjBaakY5L2pZS0tuT1lOeXZDcndzemhhZmJTWXd6QUc1RUpvWEZCCjRkK3BpV0hVRGNQeHRjYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=</data><key>DeviceCertificate</key><data>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM4ekNDQWx5Z0F3SUJBZ0lLQXhJQUdncGwvV3l3UVRBTkJna3Foa2lHOXcwQkFRVUZBREJhTVFzd0NRWUQKVlFRR0V3SlZVekVUTUJFR0ExVUVDaE1LUVhCd2JHVWdTVzVqTGpFVk1CTUdBMVVFQ3hNTVFYQndiR1VnYVZCbwpiMjVsTVI4d0hRWURWUVFERXhaQmNIQnNaU0JwVUdodmJtVWdSR1YyYVdObElFTkJNQjRYRFRJME1EWXhNekEyCk5UWXlNRm9YRFRJM01EWXhNekEyTlRZeU1Gb3dnWU14TFRBckJnTlZCQU1XSkRZMFFURXpRalEyTFVWRE9UWXQKTkRNM1JTMDRNVFE0TFRkRU5URkZOMFpGTXpGQlFqRUxNQWtHQTFVRUJoTUNWVk14Q3pBSkJnTlZCQWdUQWtOQgpNUkl3RUFZRFZRUUhFd2xEZFhCbGNuUnBibTh4RXpBUkJnTlZCQW9UQ2tGd2NHeGxJRWx1WXk0eER6QU5CZ05WCkJBc1RCbWxRYUc5dVpUQ0JuekFOQmdrcWhraUc5dzBCQVFFRkFBT0JqUUF3Z1lrQ2dZRUFnVTdXWnRhS0pzYy8KNEI4UkkwTXIwWU14SmFZT1puUlhFdXF2N3BpVDNpYkZwM3R5NzNMRkRsR1JJWUlTM2xubDRGaU1EOWxKVWd5UgpKY0FnRk4wZkV2ejY4TG1pR3FhQ1RDMnViTG5UN3BVODQwMTRFR1l1U0Vubk13b2EvZnRybVZVUVIxZVh6SEY0CkJNRTFHSXMvVU1oeHZNZ295UUt3WDBhSjd2cHdxSFVDQXdFQUFhT0JsVENCa2pBZkJnTlZIU01FR0RBV2dCU3kKL2lFalJJYVZhbm5WZ1NhT2N4RFlwMHlPZERBZEJnTlZIUTRFRmdRVVBSK0Zab1R3Z1NYd2tQRUkySkFwb29MMQp2SUV3REFZRFZSMFRBUUgvQkFJd0FEQU9CZ05WSFE4QkFmOEVCQU1DQmFBd0lBWURWUjBsQVFIL0JCWXdGQVlJCkt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01CQUdDaXFHU0liM1kyUUdDZ0lFQWdVQU1BMEdDU3FHU0liM0RRRUIKQlFVQUE0R0JBRWFCbTdteDl5Z2ZxMU5KOE5kQlMzTjF1ZnVKMnBJZ1BDSUpudHB0YkdmVkNoU2wycC80UDJIWgpUSy8wY1NOczUxbnRLZjZBc1NxYlBodzVwN3g2UDNZRGRNS0tmaHVvNHRRVXZnYmRrUkM3Skg2elRNcm5mSmdICjB2b3dSYW1UNTNlcXdvUnBPaTRTTXo0N1dYQ0V2OTYydGhBbTBNRnpGekxPR0g2bU0rYUwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=</data><key>RegulatoryInfo</key><data>eyJlbGFiZWwiOnsiYmlzIjp7InJlZ3VsYXRvcnkiOiJSLTQxMDk0ODk3In19fQ==</data><key>FairPlayKeyData</key><data>LS0tLS1CRUdJTiBDT05UQUlORVItLS0tLQpBQUVBQVQzOGVycGgzbW9HSGlITlFTMU5YcTA1QjFzNUQ2UldvTHhRYWpKODVDWEZLUldvMUI2c29Pd1kzRHUyClJtdWtIemlLOFV5aFhGV1N1OCtXNVI4dEJtM3MrQ2theGpUN2hnQVJ5S0o0U253eE4vU3U2aW9ZeDE3dVFld0IKZ1pqc2hZeitkemlXU2I4U2tRQzdFZEZZM0Z2bWswQXE3ZlVnY3JhcTZqU1g4MUZWcXc1bjNpRlQwc0NRSXhibgpBQkVCQ1JZazlodFlML3RlZ0kzc29DeUZzcmM1TTg1OXhTcHRGNFh2ejU1UVZDQkw1OFdtSzZnVFNjVHlVSDN3CjJSVERXUjNGRnJxR2Y3aTVCV1lxRVdLMEkzNFgyTWJsZnR4OTM3bmI3SysrTFVkYk81YnFZaDM0bTREcUZwbCsKZkRnaDVtdU1DNkVlWWZPeTlpdEJsbE5ad2VlUWJBUmtKa2FHUGJ5aEdpYlNCcTZzR0NrQVJ2WTltT2ZNT3hZYgplWitlNnhBRmZ4MjFwUk9BM0xZc0FmMzBycmtRc0tKODVBRHZVMzFKdUFibnpmeGQzRnorbHBXRi9FeHU5QVNtCm1XcFFTY1VZaXF5TXZHUWQ5Rnl6ZEtNYk1SQ1ExSWpGZVhOUWhWQTY0VzY4M0czbldzRjR3a3lFRHl5RnI1N2QKcUJ3dFA4djRhSXh4ZHVSODVaT0lScWs0UGlnVlUvbVRpVUVQem16Wlh2MVB3ZzNlOGpjL3pZODZoYWZHaDZsZApMbHAyTU9uakNuN1pmKzFFN0RpcTNrS280bVo0MHY0cEJOV1BodnZGZ0R5WDdSLy9UaTBvbCtnbzc1QmR2b1NpCmljckUzYUdOc0hhb0d6cE90SHVOdW5HNTh3UW9BWXMwSUhQOGNvdmxPMDhHWHVRUlh1NVYyM1VyK2ZLQ2t5dm8KSEptYWVmL29ZbmR3QzAvK1pUL2FOeTZKUUEzUzg1Y3dzaFE3YXpYajlZazNndzkzcE0xN3I5dExGejNHWDRQegoyZWhMclVOTCtZcSs1bW1zeTF6c2RlcENGMldkR09KbThnajluMjdHUDNVVnhUOVA4TkI0K1YwNzlEWXd6TEdiCjhLdGZCRExSM2cwSXppYkZQNzZ5VC9FTDUwYmlacU41SlNLYnoxS2lZSGlGS05CYnJEbDlhWWFNdnFJNHhOblgKNVdpZk43WDk3UHE0TFQzYW5rcmhUZUVqeXFxeC9kYmovMGh6bG1RRCtMaW5UV29SU2ZFVWI2Ni9peHFFb3BrbQp3V2h6dXZPMUVPaTRseUJUV09MdmxUY1h1WUpwTUpRZHNCb0dkSVdrbm80Qnp5N3BESXMvSXpNUVEzaUpEYVc3CnBiTldrSUNTdytEVWJPdDVXZFZqN0FHTEFUR2FVRW1ZS1dZNnByclo2bks0S1lReFJDN3NvdDc2SHJaajJlVnoKRVl4cm1hVy9lRHhuYVhDOGxCNXpCS0wrQ1pDVmZhWHlEdmV1MGQvdzhpNGNnRTVqSkF6S2FFcmtDeUlaSm5KdApYTkJhOEl3M3Y3aW1GNlhPREFEaU9KK3hGTjdJQXlzem5YMEw4RFJ6Mkc1d2I5clllMW03eDRHM3duaklxZG1hCm9DdzZINnNPcFFRM2RWcVd0UDhrL1FJbk5ONnV2dVhEN3kvblVsdlVqcnlVbENlcFlzeDhkOFNScWw1M3d0SGwKYWxabUpvRWh0QTdRVDBUZHVVUmJ6M2dabWVXKzJRM3BlazVHaVBKRStkci83YklHRGxhdWZJVkVQTXc4clg3agpVNTVRWmZ6MHZyc3p5eGg3U0x1SDc3RmVGd3ljVlJId0t6NkFndlpOb0R2b0dMWk9KTi82V1NxVlhmczYxUEdPCmN0d29WVkkzejhYMGtWUXRHeUpjQTlFYjN0SFBHMzMrM1RpYnBsL2R0VW1LRU5WeUUrQTJUZDN5RFRydVBFQmsKZHJhM3pFc25ZWXFxR2I3aVhvMVB6Y3crUGo5QTRpQlE2cTl3RGtBbEFDdTZsZnUwCi0tLS0tRU5EIENPTlRBSU5FUi0tLS0tCg==</data><key>AccountToken</key><data>ewoJIkludGVybmF0aW9uYWxNb2JpbGVFcXVpcG1lbnRJZGVudGl0eSIgPSAiMzU1MzI0MDg3ODI2NDIxIjsKCSJQaG9uZU51bWJlck5vdGlmaWNhdGlvblVSTCIgPSAiaHR0cHM6Ly9hbGJlcnQuYXBwbGUuY29tL2RldmljZXNlcnZpY2VzL3Bob25lSG9tZSI7CgkiU2VyaWFsTnVtYmVyIiA9ICJGNEdUR1lKWkhHN0YiOwoJIlByb2R1Y3RUeXBlIiA9ICJpUGhvbmU5LDMiOwoJIlVuaXF1ZURldmljZUlEIiA9ICIwYTQ2MzA1Y2EyZWM4MGY5N2YyOGEyMmI3Yjk3N2M0NWEwMWM4MjhhIjsKCSJXaWxkY2FyZFRpY2tldCIgPSAiTUlJQ3FnSUJBVEFMQmdrcWhraUc5dzBCQVFzeGNKOC9ESk5CQU9reEFMVHplQk5icHA5QUJHQUFBQUNmU3hSVHVlUXBnL3l6YThXakQ5cUdyMDdidWtUSUNaK0hiUWMxVXlRSWVDWkNuNWM5REFBQUFBRHU3dTd1N3U3dTc1K1hQZ1FBQUFBQW41Yy9CQUVBQUFDZmwwQUVBUUFBQUorWFFRUUJBQUFBbjVkTUJBQUFBQUFFZ2dFQUMvV0tiMWNuM3hFZjV4TVU4WGZJOWpiclUvb0ErQW4rYlFwaHlhcmc4Z3I2bU5oZ2Y2UFoxMm9FVUlpV3FzY3F3T29MU1hWcWMrZGtvbmxhSVoyYXBFVENjME9YOXYwM3Rwamd5UEloZmpoL0M1MVZLL3hKNWkwLzIvTW0wcDdUQjFRU2V2dWtiMjBKMjVBWlJaT0FFUzIyZzRvS0xGL1d3OVpnbVJicit1USs4TGE3NzlQRWx0Z3pRN2k5dG9TYW9MemxwRk10dnNMV1ZpbStadytwaFJYKzlJN1g3dVNUQzF2c1N4U1F6Wng2d1prWE4rUER6WFo4dTNhN0hWOThnazcyTHlGa0RQVTM5emxPNUY2enZoZU9WcWNmV240WEpuUFB2SVo2VnZ6SzIvbjRZM2RGSUUzaGxheVBFemF0RWxBM3NGNmFFeE1HZ0ErejZzajJLS09DQVNBd0N3WUpLb1pJaHZjTkFRRUJBNElCRHdBd2dnRUtBb0lCQVFDc2tVOUYyZHo4VHRXQnEyRDhBZHNxY1lTNTFINjZEeFptQ0hFdzZVOXAzZDh2amFFY0JkRjVWRndFVG1XSkJjVEpvL1NpUExlemRBbUc0MFJmQXN4ZzRzSW9rMENQaEtzVHAxbW9uMEpCcWFpNjhTZG1OMEwrQXNFYm1OSzRBampNWDZHTTV0N3c1bWRYcGdaeWlnUnRHUURuVjJQN0huT1pqNjlQUzlyL0Q0UTUwQ0pOYUxyR0paMVVWQk5jS2tKTlRNRDJweHJIbnhkU0xUajUxeFZJVEJVNzFUZGw3S2doU3NrUDhXYWdPT05rNkowSWNPQ3dJYVdjdDlBLytBc280eWs1L1BEaDFZVWhiVWlJTyt6MVRMNVRkaUhMSVRnYzhOWEhhZ0IveWlPRUV6T3gycGNaVlhYandmU1psS1JIajY2VmxXVkhnVCtiRUhabDAvc2RBZ01CQUFFPSI7CgkiUG9zdHBvbmVtZW50SW5mbyIgPSB7fTsKCSJBY3RpdmF0aW9uUmFuZG9tbmVzcyIgPSAiMTY0NDdBODUtQkNFNS00REY4LTgxMTItQ0NENTQzMUQ2MzUyIjsKCSJBY3Rpdml0eVVSTCIgPSAiaHR0cHM6Ly9hbGJlcnQuYXBwbGUuY29tL2RldmljZXNlcnZpY2VzL2FjdGl2aXR5IjsKfQ==</data><key>AccountTokenSignature</key><data>cSXDrh9USyHuC8Uj4Wf/HAQtGK5198e6adrS8e7HDu4japjBxPjVFRd4z0+POFPxF4+A9eTyf8U0C/QS1/KZq8uZWFW9G+yczsk4rurvL7SaNr641Ee4MTm6owVdW8ORDhFfvA2CB5JgUgj+GJbUx0J89cweFggqAyDAlgxIy4s=</data><key>UniqueDeviceCertificate</key><data>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURqRENDQXpLZ0F3SUJBZ0lHQVpBUVloQWZNQW9HQ0NxR1NNNDlCQU1DTUVVeEV6QVJCZ05WQkFnTUNrTmgKYkdsbWIzSnVhV0V4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEdUQVhCZ05WQkFNTUVFWkVVa1JETFZWRApVbFF0VTFWQ1EwRXdIaGNOTWpRd05qRXpNRFkwTmpJd1doY05NalF3TmpJd01EWTFOakl3V2pCdU1STXdFUVlEClZRUUlEQXBEWVd4cFptOXlibWxoTVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1SNHdIQVlEVlFRTERCVjEKWTNKMElFeGxZV1lnUTJWeWRHbG1hV05oZEdVeElqQWdCZ05WQkFNTUdUQXdNREE0TURFd0xUQXdNVGcwT1VVMApNREEyUVRRek1qWXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBU2xaeVJycFRTMEZWWGphYWdoCnJlMTh2RFJPd1ZEUEZMeC9CNzE2aXhqamZyaVMvcmhrN0xtOENHSXJmWWxlOTBobUV0YUdCSlBVOFM0UUhGRmgKL0d2U280SUI0ekNDQWQ4d0RBWURWUjBUQVFIL0JBSXdBREFPQmdOVkhROEJBZjhFQkFNQ0JQQXdnZ0ZNQmdrcQpoa2lHOTJOa0NnRUVnZ0U5TVlJQk9mK0VrcjJrUkFzd0NSWUVRazlTUkFJQkRQK0VtcUdTVUEwd0N4WUVRMGhKClVBSURBSUFRLzRTcWpaSkVFVEFQRmdSRlEwbEVBZ2NZU2VRQWFrTW0vNGFUdGNKakd6QVpGZ1JpYldGakJCRmoKTURwa01Eb3hNanBpTlRveVlqbzROLytHeTdYS2FSa3dGeFlFYVcxbGFRUVBNelUxTXpJME1EZzNPREkyTkRJeAovNGVieWR4dEZqQVVGZ1J6Y201dEJBeEdORWRVUjFsS1draEhOMGIvaDZ1UjBtUXlNREFXQkhWa2FXUUVLREJoCk5EWXpNRFZqWVRKbFl6Z3daamszWmpJNFlUSXlZamRpT1RjM1l6UTFZVEF4WXpneU9HSC9oN3Uxd21NYk1Ca1cKQkhkdFlXTUVFV013T21Rd09qRXlPbUkxT2pKaU9qZzIvNGVibGRKa09qQTRGZ1J6Wldsa0JEQXdOREk0TWtaRgpNelEyTTBVNE1EQXhOak15TURFeU56WXlNamt6T1RrNU56WkRRVVpHTkRrME5USTNSRVUyTVRFd01nWUtLb1pJCmh2ZGpaQVlCRHdRa01TTC9oT3FGbkZBS01BZ1dCRTFCVGxBeEFQK0Urb21VVUFvd0NCWUVUMEpLVURFQU1CSUcKQ1NxR1NJYjNZMlFLQWdRRk1BTUNBUUF3SndZSktvWklodmRqWkFnSEJCb3dHTCtLZUFnRUJqRTFMamN1TTcrSwpld2dFQmpFNVNETXdOekFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBeDV4SVhUZDZUb1d4RXlWN2krMWZLeGNsCm5hR3ZZR254QXF0QkRJSTlOME1DSUVpUWlWZEhDamNFRFhWS3dDLzhidWZzZVBweXBXSjVRMlppbW9Vb1d4Sk0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLXVrTXRIOVJkU1F2SHpCeDdGaUJHcjcvS2NtbHhYL1h3b1dlV25XYjZJUk09Ci0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDRnpDQ0FaeWdBd0lCQWdJSU9jVXFROElDL2hzd0NnWUlLb1pJemowRUF3SXdRREVVTUJJR0ExVUVBd3dMClUwVlFJRkp2YjNRZ1EwRXhFekFSQmdOVkJBb01Da0Z3Y0d4bElFbHVZeTR4RXpBUkJnTlZCQWdNQ2tOaGJHbG0KYjNKdWFXRXdIaGNOTVRZd05ESTFNak0wTlRRM1doY05Namt3TmpJME1qRTBNekkwV2pCRk1STXdFUVlEVlFRSQpEQXBEWVd4cFptOXlibWxoTVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Sa3dGd1lEVlFRRERCQkdSRkpFClF5MVZRMUpVTFZOVlFrTkJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVhRGMyTy9NcnVZdlAKVlBhVWJLUjdSUnpuNjZCMTQvOEtvVU1zRURiN25Ia0dFTVg2ZUMrMGdTdEdIZTRIWU1yTHlXY2FwMXRERlltRQpEeWtHUTN1TTJhTjdNSGt3SFFZRFZSME9CQllFRkxTcU9rT3RHK1YremdvTU9CcTEwaG5MbFRXek1BOEdBMVVkCkV3RUIvd1FGTUFNQkFmOHdId1lEVlIwakJCZ3dGb0FVV08vV3ZzV0NzRlROR0thRXJhTDJlM3M2Zjg4d0RnWUQKVlIwUEFRSC9CQVFEQWdFR01CWUdDU3FHU0liM1kyUUdMQUVCL3dRR0ZnUjFZM0owTUFvR0NDcUdTTTQ5QkFNQwpBMmtBTUdZQ01RRGY1ek5paUtOL0pxbXMxdyszQ0RZa0VTT1BpZUpNcEVrTGU5YTBValdYRUJETDBWRXNxL0NkCkUzYUtYa2M2UjEwQ01RRFM0TWlXaXltWStSeGt2eS9oaWNERFFxSS9CTCtOM0xIcXpKWlV1dzJTeDBhZkRYN0IKNkx5S2src0xxNHVya01ZPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t</data></dict></dict></plist></script>
      <script>
		var protocolElement = document.getElementById("protocol");
		var protocolContent = protocolElement.innerText;
		iTunes.addProtocol(protocolContent);
      </script>
   </head>
   <body>
   </body>
</html>
[end of 3 deviceActivation/deviceActivation_response.txt]

[start of 5 deviceActivation/deviceActivation_response.txt]
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
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
</html>
[end of 5 deviceActivation/deviceActivation_response.txt]
