import json
import uuid

from flask import render_template, flash, redirect, url_for, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, HiddenField, validators

from app.config import RP_ID, URL
from app.dashboard.base import dashboard_bp
from app.dashboard.views.enter_sudo import sudo_required
from app.db import Session
from app.log import LOG
from app.models import Fido, RecoveryCode
from app.user_settings import regenerate_user_alternative_id
from app.webauthn_utils import (
    CredentialOption,
    new_challenge,
    registration_options,
    verify_registration,
)


class FidoTokenForm(FlaskForm):
    key_name = StringField("key_name", validators=[validators.DataRequired()])
    sk_assertion = HiddenField("sk_assertion", validators=[validators.DataRequired()])


@dashboard_bp.route("/fido_setup", methods=["GET", "POST"])
@login_required
@sudo_required
def fido_setup():
    if current_user.fido_uuid is not None:
        fidos = Fido.filter_by(uuid=current_user.fido_uuid).all()
    else:
        fidos = []

    fido_token_form = FidoTokenForm()

    # Handling POST requests
    if fido_token_form.validate_on_submit():
        fido_uuid = session.pop("fido_uuid", None)
        challenge = session.pop("fido_challenge", None)
        if not (fido_uuid and challenge):
            flash("Session expired. Please try again.", "warning")
            return redirect(url_for("dashboard.index"))
        try:
            sk_assertion = json.loads(fido_token_form.sk_assertion.data)
        except Exception:
            flash("Key registration failed. Error: Invalid Payload", "warning")
            return redirect(url_for("dashboard.index"))

        try:
            fido_credential = verify_registration(
                credential=sk_assertion,
                challenge=challenge,
                rp_id=RP_ID,
                origin=URL,
            )
        except Exception as e:
            LOG.w(f"An error occurred in WebAuthn registration process: {e}")
            flash("Key registration failed.", "warning")
            return redirect(url_for("dashboard.index"))

        if current_user.fido_uuid is None:
            current_user.fido_uuid = fido_uuid
            Session.flush()

        response = sk_assertion.get("response", {})
        transports = response.get("transports") if isinstance(response, dict) else None
        Fido.create(
            credential_id=fido_credential.credential_id,
            uuid=fido_uuid,
            public_key=fido_credential.public_key,
            sign_count=fido_credential.sign_count,
            name=fido_token_form.key_name.data,
            user_id=current_user.id,
            credential_type=fido_credential.credential_type,
            authenticator_attachment=sk_assertion.get("authenticatorAttachment"),
            transports=transports if isinstance(transports, list) else None,
            aaguid=fido_credential.aaguid,
        )
        regenerate_user_alternative_id(current_user)
        Session.commit()

        LOG.d(f"credential_id={fido_credential.credential_id} added for {fido_uuid}")

        flash("Security key has been activated", "success")
        recovery_codes = RecoveryCode.generate(current_user)
        return render_template(
            "dashboard/recovery_code.html", recovery_codes=recovery_codes
        )

    # Prepare information for key registration process
    fido_uuid = (
        str(uuid.uuid4()) if current_user.fido_uuid is None else current_user.fido_uuid
    )
    challenge = new_challenge()
    registration_dict = registration_options(
        rp_id=RP_ID,
        user_id=fido_uuid,
        user_email=current_user.email,
        user_display_name=current_user.name or current_user.email,
        challenge=challenge,
        existing_credentials=[
            CredentialOption(fido.credential_id, fido.transports) for fido in fidos
        ],
    )

    session["fido_uuid"] = fido_uuid
    session["fido_challenge"] = challenge

    return render_template(
        "dashboard/fido_setup.html",
        fido_token_form=fido_token_form,
        credential_create_options=registration_dict,
    )
