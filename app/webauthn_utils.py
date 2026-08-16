from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    UserVerificationRequirement,
)

SUPPORTED_PUBLIC_KEY_ALGORITHMS = [
    COSEAlgorithmIdentifier.EDDSA,
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
    # Older SimpleLogin releases advertised PS256. Keep already-issued and new
    # PS256 credentials valid while moving to the current WebAuthn verifier.
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
]


@dataclass(frozen=True)
class CredentialOption:
    credential_id: str
    transports: Sequence[str] | None = None


@dataclass(frozen=True)
class RegistrationResult:
    credential_id: str
    public_key: str
    sign_count: int
    aaguid: str
    credential_type: str


def new_challenge() -> str:
    """Return a cryptographically random, session-safe WebAuthn challenge."""
    return bytes_to_base64url(secrets.token_bytes(32))


def _challenge_bytes(challenge: str) -> bytes:
    if not challenge:
        raise ValueError("WebAuthn challenge is missing")
    return base64url_to_bytes(challenge)


def _transports(values: Iterable[str] | None) -> list[AuthenticatorTransport]:
    transports: list[AuthenticatorTransport] = []
    for value in values or ():
        try:
            transport = AuthenticatorTransport(value)
        except ValueError:
            continue
        if transport not in transports:
            transports.append(transport)
    return transports


def _descriptor(option: CredentialOption) -> PublicKeyCredentialDescriptor:
    transports = _transports(option.transports)
    return PublicKeyCredentialDescriptor(
        id=base64url_to_bytes(option.credential_id),
        transports=transports or None,
    )


def registration_options(
    *,
    rp_id: str,
    user_id: str,
    user_email: str,
    user_display_name: str,
    challenge: str,
    existing_credentials: Sequence[CredentialOption],
) -> dict[str, Any]:
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="SimpleLogin",
        user_id=user_id.encode("utf-8"),
        user_name=user_email,
        user_display_name=user_display_name,
        challenge=_challenge_bytes(challenge),
        attestation=AttestationConveyancePreference.NONE,
        exclude_credentials=[_descriptor(item) for item in existing_credentials],
        supported_pub_key_algs=SUPPORTED_PUBLIC_KEY_ALGORITHMS,
    )
    return json.loads(options_to_json(options))


def verify_registration(
    *,
    credential: Mapping[str, Any],
    challenge: str,
    rp_id: str,
    origin: str,
) -> RegistrationResult:
    verified = verify_registration_response(
        credential=dict(credential),
        expected_challenge=_challenge_bytes(challenge),
        expected_rp_id=rp_id,
        expected_origin=origin,
        require_user_presence=True,
        require_user_verification=False,
        supported_pub_key_algs=SUPPORTED_PUBLIC_KEY_ALGORITHMS,
    )
    return RegistrationResult(
        credential_id=bytes_to_base64url(verified.credential_id),
        public_key=bytes_to_base64url(verified.credential_public_key),
        sign_count=verified.sign_count,
        aaguid=verified.aaguid,
        credential_type=verified.credential_type.value,
    )


def authentication_options(
    *,
    rp_id: str,
    challenge: str,
    credentials: Sequence[CredentialOption],
    require_user_verification: bool = False,
    hardware_hint: bool = False,
) -> dict[str, Any]:
    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=_challenge_bytes(challenge),
        allow_credentials=[_descriptor(item) for item in credentials],
        user_verification=(
            UserVerificationRequirement.REQUIRED
            if require_user_verification
            else UserVerificationRequirement.DISCOURAGED
        ),
    )
    serialized = json.loads(options_to_json(options))
    if hardware_hint:
        serialized["hints"] = [
            PublicKeyCredentialHint.SECURITY_KEY.value,
            PublicKeyCredentialHint.CLIENT_DEVICE.value,
        ]
        for descriptor in serialized.get("allowCredentials", []):
            descriptor["transports"] = [
                AuthenticatorTransport.USB.value,
                AuthenticatorTransport.NFC.value,
            ]
    return serialized


def verify_authentication(
    *,
    credential: Mapping[str, Any],
    challenge: str,
    rp_id: str,
    origin: str,
    credential_id: str,
    public_key: str,
    current_sign_count: int,
    require_user_verification: bool = False,
) -> int:
    verified = verify_authentication_response(
        credential=dict(credential),
        expected_challenge=_challenge_bytes(challenge),
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=base64url_to_bytes(public_key),
        credential_current_sign_count=current_sign_count,
        require_user_verification=require_user_verification,
    )
    if verified.credential_id != base64url_to_bytes(credential_id):
        raise ValueError("WebAuthn credential identifier does not match stored key")
    return verified.new_sign_count
