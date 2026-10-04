import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from app.webauthn_utils import (
    CredentialOption,
    authentication_options,
    registration_options,
    verify_authentication,
    verify_registration,
)

RP_ID = "aliases.example.com"
ORIGIN = "https://aliases.example.com"
REGISTRATION_CHALLENGE = bytes_to_base64url(b"registration-challenge-32-bytes")
AUTHENTICATION_CHALLENGE = bytes_to_base64url(b"authentication-challenge-32bytes")
CREDENTIAL_ID = b"owned-provider-credential"


def _client_data(ceremony_type: str, challenge: str, origin: str = ORIGIN) -> bytes:
    return json.dumps(
        {
            "type": ceremony_type,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()


def _registration_credential(private_key: ec.EllipticCurvePrivateKey) -> dict:
    public_numbers = private_key.public_key().public_numbers()
    cose_public_key = cbor2.dumps(
        {
            1: 2,  # EC2
            3: -7,  # ES256
            -1: 1,  # P-256
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        }
    )
    authenticator_data = b"".join(
        (
            hashlib.sha256(RP_ID.encode()).digest(),
            b"\x41",  # user present and attested credential data
            (0).to_bytes(4, "big"),
            uuid.UUID("12345678-1234-5678-1234-567812345678").bytes,
            len(CREDENTIAL_ID).to_bytes(2, "big"),
            CREDENTIAL_ID,
            cose_public_key,
        )
    )
    attestation_object = cbor2.dumps(
        {"fmt": "none", "attStmt": {}, "authData": authenticator_data}
    )
    client_data = _client_data("webauthn.create", REGISTRATION_CHALLENGE)
    credential_id = bytes_to_base64url(CREDENTIAL_ID)
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {
            "attestationObject": bytes_to_base64url(attestation_object),
            "clientDataJSON": bytes_to_base64url(client_data),
            "transports": ["usb"],
        },
        "clientExtensionResults": {},
        "authenticatorAttachment": "cross-platform",
    }


def _authentication_credential(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    challenge: str = AUTHENTICATION_CHALLENGE,
    sign_count: int = 1,
) -> dict:
    client_data = _client_data("webauthn.get", challenge)
    authenticator_data = b"".join(
        (
            hashlib.sha256(RP_ID.encode()).digest(),
            b"\x05",  # user present and user verified
            sign_count.to_bytes(4, "big"),
        )
    )
    signature = private_key.sign(
        authenticator_data + hashlib.sha256(client_data).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    credential_id = bytes_to_base64url(CREDENTIAL_ID)
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {
            "authenticatorData": bytes_to_base64url(authenticator_data),
            "clientDataJSON": bytes_to_base64url(client_data),
            "signature": bytes_to_base64url(signature),
            "userHandle": None,
        },
        "clientExtensionResults": {},
        "authenticatorAttachment": "cross-platform",
    }


def _packed_registration_credential(
    credential_key: ec.EllipticCurvePrivateKey,
    attestation_key: ec.EllipticCurvePrivateKey,
) -> dict:
    credential = _registration_credential(credential_key)
    response = credential["response"]
    client_data = base64url_to_bytes(response["clientDataJSON"])
    attestation = cbor2.loads(base64url_to_bytes(response["attestationObject"]))

    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Authenticator"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, "Owned Provider Test Key"),
        ]
    )
    now = datetime(2025, 1, 1, tzinfo=UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(attestation_key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(attestation_key, hashes.SHA256())
    )
    signature = attestation_key.sign(
        attestation["authData"] + hashlib.sha256(client_data).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    response["attestationObject"] = bytes_to_base64url(
        cbor2.dumps(
            {
                "fmt": "packed",
                "authData": attestation["authData"],
                "attStmt": {
                    "alg": -7,
                    "sig": signature,
                    "x5c": [certificate.public_bytes(serialization.Encoding.DER)],
                },
            }
        )
    )
    return credential


def test_real_registration_and_authentication_ceremonies():
    private_key = ec.derive_private_key(7, ec.SECP256R1())
    registration = verify_registration(
        credential=_registration_credential(private_key),
        challenge=REGISTRATION_CHALLENGE,
        rp_id=RP_ID,
        origin=ORIGIN,
    )

    assert registration.credential_id == bytes_to_base64url(CREDENTIAL_ID)
    assert registration.aaguid == "12345678-1234-5678-1234-567812345678"
    assert registration.credential_type == "public-key"

    new_sign_count = verify_authentication(
        credential=_authentication_credential(private_key),
        challenge=AUTHENTICATION_CHALLENGE,
        rp_id=RP_ID,
        origin=ORIGIN,
        credential_id=registration.credential_id,
        public_key=registration.public_key,
        current_sign_count=0,
        require_user_verification=True,
    )
    assert new_sign_count == 1


def test_authentication_rejects_replayed_counter():
    private_key = ec.derive_private_key(7, ec.SECP256R1())
    registration = verify_registration(
        credential=_registration_credential(private_key),
        challenge=REGISTRATION_CHALLENGE,
        rp_id=RP_ID,
        origin=ORIGIN,
    )

    with pytest.raises(Exception, match="sign count"):
        verify_authentication(
            credential=_authentication_credential(private_key),
            challenge=AUTHENTICATION_CHALLENGE,
            rp_id=RP_ID,
            origin=ORIGIN,
            credential_id=registration.credential_id,
            public_key=registration.public_key,
            current_sign_count=1,
            require_user_verification=True,
        )


def test_options_preserve_existing_credentials_and_admin_policy():
    stored = CredentialOption(bytes_to_base64url(CREDENTIAL_ID), ["usb", "nfc"])
    registration = registration_options(
        rp_id=RP_ID,
        user_id="f2dcad6e-90c7-46d8-8dc6-f830bd81381c",
        user_email="operator@example.com",
        user_display_name="Operator",
        challenge=REGISTRATION_CHALLENGE,
        existing_credentials=[stored],
    )
    authentication = authentication_options(
        rp_id=RP_ID,
        challenge=AUTHENTICATION_CHALLENGE,
        credentials=[stored],
        require_user_verification=True,
        hardware_hint=True,
    )

    assert registration["excludeCredentials"] == [
        {
            "id": bytes_to_base64url(CREDENTIAL_ID),
            "transports": ["usb", "nfc"],
            "type": "public-key",
        }
    ]
    assert any(item["alg"] == -37 for item in registration["pubKeyCredParams"])
    assert authentication["userVerification"] == "required"
    assert authentication["allowCredentials"][0]["transports"] == ["usb", "nfc"]


def test_registration_rejects_wrong_origin():
    private_key = ec.derive_private_key(7, ec.SECP256R1())
    with pytest.raises(Exception, match="origin"):
        verify_registration(
            credential=_registration_credential(private_key),
            challenge=REGISTRATION_CHALLENGE,
            rp_id=RP_ID,
            origin="https://attacker.example",
        )


def test_registration_verifies_packed_x509_attestation():
    registration = verify_registration(
        credential=_packed_registration_credential(
            ec.derive_private_key(7, ec.SECP256R1()),
            ec.derive_private_key(11, ec.SECP256R1()),
        ),
        challenge=REGISTRATION_CHALLENGE,
        rp_id=RP_ID,
        origin=ORIGIN,
    )
    assert registration.credential_id == bytes_to_base64url(CREDENTIAL_ID)


@pytest.mark.parametrize(
    ("challenge", "rp_id"),
    [
        (bytes_to_base64url(b"wrong-challenge-32-byte-value"), RP_ID),
        (AUTHENTICATION_CHALLENGE, "attacker.example"),
    ],
)
def test_authentication_rejects_wrong_ceremony_binding(challenge, rp_id):
    private_key = ec.derive_private_key(7, ec.SECP256R1())
    registration = verify_registration(
        credential=_registration_credential(private_key),
        challenge=REGISTRATION_CHALLENGE,
        rp_id=RP_ID,
        origin=ORIGIN,
    )
    with pytest.raises(Exception):
        verify_authentication(
            credential=_authentication_credential(private_key),
            challenge=challenge,
            rp_id=rp_id,
            origin=ORIGIN,
            credential_id=registration.credential_id,
            public_key=registration.public_key,
            current_sign_count=0,
        )


def test_authentication_rejects_unknown_and_malformed_credentials():
    private_key = ec.derive_private_key(7, ec.SECP256R1())
    registration = verify_registration(
        credential=_registration_credential(private_key),
        challenge=REGISTRATION_CHALLENGE,
        rp_id=RP_ID,
        origin=ORIGIN,
    )
    credential = _authentication_credential(private_key)
    with pytest.raises(ValueError, match="identifier"):
        verify_authentication(
            credential=credential,
            challenge=AUTHENTICATION_CHALLENGE,
            rp_id=RP_ID,
            origin=ORIGIN,
            credential_id=bytes_to_base64url(b"unknown-credential"),
            public_key=registration.public_key,
            current_sign_count=0,
        )

    credential["response"]["signature"] = "not-base64url!"
    with pytest.raises(Exception):
        verify_authentication(
            credential=credential,
            challenge=AUTHENTICATION_CHALLENGE,
            rp_id=RP_ID,
            origin=ORIGIN,
            credential_id=registration.credential_id,
            public_key=registration.public_key,
            current_sign_count=0,
        )
