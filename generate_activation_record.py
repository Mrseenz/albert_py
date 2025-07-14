import plistlib
import argparse
import base64
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
import json
from datetime import datetime, timezone


def generate_device_certificate(device_info):
    """Generate a PEM device certificate based on real device info (Apple format)"""
    # Generate device private key
    device_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Create device certificate subject (Apple format: CN=UUID, then location info)
    device_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{device_info['UniqueDeviceID']}"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Cupertino"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "iPhone"),
    ])

    # Create a dummy CA for signing the device certificate
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
        x509.NameAttribute(NameOID.COMMON_NAME, "Apple Root CA"),
    ])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc).replace(year=datetime.now().year + 10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )

    # Create device certificate
    device_certificate = x509.CertificateBuilder().subject_name(
        device_subject
    ).issuer_name(
        ca_certificate.subject
    ).public_key(
        device_private_key.public_key()
    ).serial_number(
        int.from_bytes(bytes.fromhex(device_info['UniqueDeviceID'].replace('-', '')[:16]), 'big')
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc).replace(year=datetime.now().year + 5)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=False,
            crl_sign=False,
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256())

    # Return PEM format (not DER) - Apple expects PEM certificates
    pem_cert = device_certificate.public_bytes(Encoding.PEM)
    return pem_cert

def _generate_custom_account_token(data):
    """Generate the custom-formatted account token string matching Apple's exact format."""
    lines = ['{']
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f'\t"{key}" = {{}};')
        else:
            # Ensure proper quoting for string values
            value_str = str(value).replace('"', '\\"')
            lines.append(f'\t"{key}" = "{value_str}";')
    lines.append('}')
    return '\n'.join(lines)

def generate_activation_record(device_info):
    """Generate a complete activation record based on Apple's exact structure from sample"""
    # Generate certificates (DER format, base64 encoded in sample)
    device_cert = generate_device_certificate(device_info)
    account_token_cert = generate_device_certificate(device_info)  # Reuse for simplicity
    unique_device_cert = generate_device_certificate(device_info)  # Reuse for simplicity

    # Generate account token data (based on sample structure)
    account_token_data = {
        'InternationalMobileEquipmentIdentity': device_info['IMEI'],
        'ActivationTicket': 'MIIBkgIBATAKBggqhkjOPQQDAzGBn58/BKcA1TCfQAThQBQAn0sUdX6tnBBhMW260aE7qDygjGpKSgKfh20HNWIoMpSJJp+IAAc1YigyaTIzn5c9GAAAAA' + base64.b64encode(os.urandom(256)).decode('utf-8'),
        'PhoneNumberNotificationURL': 'https://albert.apple.com/deviceservices/phoneHome',
        'InternationalMobileSubscriberIdentity': device_info.get('ICCID', '655015840487965'),
        'ProductType': device_info['ProductType'],
        'UniqueDeviceID': device_info['UniqueDeviceID'],
        'SerialNumber': device_info['SerialNumber'],
        'MobileEquipmentIdentifier': device_info['MEID'],
        'InternationalMobileEquipmentIdentity2': device_info['IMEI'],
        'PostponementInfo': {},
        'ActivationRandomness': base64.b64encode(os.urandom(16)).decode('utf-8').replace('=', '').upper()[:32] + '-' + base64.b64encode(os.urandom(16)).decode('utf-8').replace('=', '').upper()[:4] + '-' + base64.b64encode(os.urandom(16)).decode('utf-8').replace('=', '').upper()[:4] + '-' + base64.b64encode(os.urandom(16)).decode('utf-8').replace('=', '').upper()[:4] + '-' + base64.b64encode(os.urandom(16)).decode('utf-8').replace('=', '').upper()[:12],
        'ActivityURL': 'https://albert.apple.com/deviceservices/activity',
        'IntegratedCircuitCardIdentity': device_info.get('ICCID', '89584000000004879653')
    }

    # Generate the custom-formatted account token string (Apple's specific format)
    account_token_str = _generate_custom_account_token(account_token_data)
    # Convert to bytes for proper <data> tag generation
    account_token = account_token_str.encode('utf-8')

    # Generate realistic regulatory info (JSON format) - exact match to sample
    regulatory_info_dict = {
        'manufacturingDate': '2023-09-20T03:22:16Z',
        'elabel': {
            'bis': {
                'regulatory': 'R-41094897'
            }
        },
        'countryOfOrigin': {
            'madeIn': 'CHN'
        }
    }
    # Convert to bytes for proper <data> tag generation
    regulatory_info = json.dumps(regulatory_info_dict).encode('utf-8')

    # Generate FairPlay container data (exact format from sample)
    fairplay_container_str = (
        "-----BEGIN CONTAINER-----\n"
        "AAEAASLbvefBBzDXZzohujxrTldM54KzepentpZ5bNwN8WDN58A9tpBoqbY+OcUS\n"
        "qxFoztjs/EMtpwboOUZzg9z+JdWkdwtLa9VSP2xVWuxn7ww9yr43ziCdGAOavaUp\n"
        "txZyNN81tmrI5whjyuoros8Cvq5IYHskz31trYZdn+nvyigkc9a9VnWqGTkiEnOT\n"
        "YCIp/dLYk5gWl5VwS+/dBcXrYOutmVKS6KPLf42Q019ssPv50wP+SQRTi+2k4OD+\n"
        "LGe9s8sMWVS146ouRIDzOGlk7x/Auap7j61CstITMU0NGVcS9xD71kJyxxOSEeP\n"
        "rjYy9F9j6upWgne+bIBEPgXSUTQCbdc9yo+beKw2EL++qJeNvl52OHrGbvkG+oDU\n"
        "jCSrNueaq7CPFXwiwrXZp3Bes68MedlDqaFRxteOPbtAyQMmcFq2VJuOzRkMhYGg\n"
        "qK/Qeqzs5f9U9QVtuRlpw7bAhHM2/bhDZkqtRolciciuB0FcnSO/fFglCOFlh1yZ\n"
        "CQPx3Evakj1pub+pi/bUOVxcBz5ONiBAaApPN+w/L/eb5yVsrLW+ouGe5bpvTJTM\n"
        "6uKeHuZszP1nvVMS4ZlgPQNoElukn4sVO2S+ojE0snmaqkDksnf1YDTeAAw+k56Y\n"
        "WNjxP5QSkh//CaQYfIMYQCyruv1wOMeMpTjVDqb/FUbegcm/swmRAocJkdFmepjp\n"
        "xyLRNTT2Y/mwpV0FDKyEqBSg+zOdnHo6leioVxw1D4qmY7CDnqUsbC7P3nULpXSv\n"
        "o7p3ZwmnU4C6KajEok6+llc10PAcw9s/ErUk93LC08lAM6ewNvLIU0PQ/IFGlSbf\n"
        "xuC70D0iV0+CxntVeZptuqqtYelUdVvN5q68JkzQHn3RsBvCjR/fcjMJ4FbD2kBL\n"
        "Avf3LvV7rAVfPmqE734ZY/kFmzzZkzdRpoDQ1uBeV8IR0+g+yjOcWDYYiWqCkjRh\n"
        "B4UVfEguOpxLLTAP7a6c1DjPJDArgvEVjIpBHzeV75r/JP5QQGcCN40eDFdcckI9\n"
        "HZyfwUHEr2vt/mj+ZKRJQXiG51ehxFCYdjwQpN9LH6N9BoZrYaZwPVPPCzYum7H5\n"
        "Zbv3Jd6lP2dlVKVH3fdcis6IhOVVIabBwclHE8IV2EV9yJJRv/jy2WZDF/Thd4cT\n"
        "zToSVXvnBi2zwwLwYAFQuGfWkaekYLY70h1k1mgt8lQkVQOdTYnNfJmO+YK9HUKg\n"
        "9TBnV2o73dY43HYxt+AzSPIiaul1D/ZV98YgLNVBmOIeo8iUDe58tgnTuUl3poPY\n"
        "I5SZzSqffdoO+HQYer72Uj4PBGxqJtOx7LttBGg8Gw7k2mA9Ts2GqQeRkUk61QDD\n"
        "yoRU0gplXAy6fD1EuJ5YBkhISPBPGXaijiAR9vtNKd0ItABBl/zoU9ZdxpnNKHOF\n"
        "KrAowIYnND+HtQr1sgWs+7sanIKfzYAB8oDhEIvqEF8/GV2IEv8rE5aThLuWXF5K\n"
        "wUtkGX6Aoa5EYUUsjZT2pzBGr2YcB+mCt3McWhbKGospaYtI\n"
        "-----END CONTAINER-----\n"
    )
    # Convert to bytes for proper <data> tag generation
    fairplay_container = fairplay_container_str.encode('utf-8')

    # Generate AccountTokenSignature (128 bytes random data)
    account_token_signature = os.urandom(128)

    # Create the inner activation record (matching Apple's exact structure)
    # All binary data as bytes objects to generate proper <data></data> tags in plist
    inner_activation_record = {
        'unbrick': True,
        'AccountTokenCertificate': account_token_cert,
        'DeviceCertificate': device_cert,
        'RegulatoryInfo': regulatory_info,
        'FairPlayKeyData': fairplay_container,
        'AccountToken': account_token,
        'AccountTokenSignature': account_token_signature,
        'UniqueDeviceCertificate': unique_device_cert
    }

    return inner_activation_record

def main():
    parser = argparse.ArgumentParser(description="Generate an activation record.")
    parser.add_argument("--input", required=True, help="Path to a file containing the activation info")
    parser.add_argument("--output", required=True, help="Path to save the generated activation record")
    args = parser.parse_args()

    with open(args.input, 'r') as f:
        activation_info_raw = f.read()

    # The activation info is a multipart form data, so we need to extract the plist
    import re
    match = re.search(r'<dict>.*</dict>', activation_info_raw, re.DOTALL)
    if not match:
        raise ValueError("Could not find plist in activation info")
    activation_info_plist = match.group(0)

    activation_info = plistlib.loads(activation_info_plist.encode('utf-8'))

    device_info = {
        'UniqueDeviceID': activation_info['UniqueDeviceID'],
        'IMEI': activation_info['InternationalMobileEquipmentIdentity'],
        'MEID': activation_info['MobileEquipmentIdentifier'],
        'SerialNumber': activation_info['SerialNumber'],
        'ProductType': activation_info['ProductType'],
        'ICCID': activation_info['IntegratedCircuitCardIdentity']
    }

    activation_record = generate_activation_record(device_info)

    with open(args.output, 'wb') as f:
        plistlib.dump(activation_record, f)

    print(f"✅ Activation record generated and saved to {args.output}")

if __name__ == "__main__":
    main()
