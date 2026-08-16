import json

from flask import render_template, flash, redirect, url_for, session, request
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from time import time
from wtforms import HiddenField, validators

from app.config import ADMIN_FIDO_REQUIRED, RP_ID, URL
from app.dashboard.base import dashboard_bp
from app.db import Session
from app.extensions import limiter
from app.log import LOG
from app.models import Fido
from app.utils import sanitize_next_url
from app.webauthn_utils import (
    CredentialOption,
    authentication_options,
    new_challenge,
    verify_authentication,
)


class FidoTokenForm(FlaskForm):
    sk_assertion = HiddenField("sk_assertion", validators=[validators.DataRequired()])


@dashboard_bp.route("/enter_admin", methods=["GET", "POST"])
@limiter.limit("10/minute")
@login_required
def enter_admin():
    next_url = sanitize_next_url(request.args.get("next"))
    if ADMIN_FIDO_REQUIRED == "none":
        return redirect(next_url or url_for("dashboard.index"))

    if not current_user.fido_enabled():
        flash(
            "A security key is required for admin access but none is configured on your account.",
            "warning",
        )
        return redirect(url_for("dashboard.index"))

    fido_token_form = FidoTokenForm()

    if fido_token_form.validate_on_submit():
        try:
            sk_assertion = json.loads(fido_token_form.sk_assertion.data)
        except Exception:
            flash("Key verification failed. Error: Invalid Payload", "warning")
            return redirect(
                url_for("dashboard.enter_admin", next=request.args.get("next"))
            )

        challenge = session.pop("admin_fido_challenge", None)
        if not challenge:
            flash("Session expired. Please try again.", "warning")
            return redirect(
                url_for("dashboard.enter_admin", next=request.args.get("next"))
            )

        try:
            fido_key = Fido.get_by(
                uuid=current_user.fido_uuid, credential_id=sk_assertion["id"]
            )
            if not fido_key:
                raise ValueError("Unknown WebAuthn credential")
            authenticator_attachment = sk_assertion.get("authenticatorAttachment")
            if ADMIN_FIDO_REQUIRED == "hardware" and (
                authenticator_attachment != "cross-platform"
                or fido_key.authenticator_attachment not in (None, "cross-platform")
            ):
                raise ValueError("Credential is not a cross-platform security key")
            new_sign_count = verify_authentication(
                credential=sk_assertion,
                challenge=challenge,
                rp_id=RP_ID,
                origin=URL,
                credential_id=fido_key.credential_id,
                public_key=fido_key.public_key,
                current_sign_count=fido_key.sign_count,
                require_user_verification=True,
            )
        except Exception as e:
            LOG.w(f"Admin {current_user} FIDO verification failed: %s", e)
            flash("Key verification failed.", "warning")
            return redirect(
                url_for("dashboard.enter_admin", next=request.args.get("next"))
            )

        fido_key.sign_count = new_sign_count
        Session.commit()

        session["admin_time"] = int(time())
        session["admin_hardware_auth"] = authenticator_attachment == "cross-platform"

        LOG.d(f"Admin {current_user} FIDO auth success for user %s", current_user.id)

        if next_url:
            return redirect(next_url)
        return redirect(url_for("dashboard.index"))

    # Prepare FIDO challenge
    session.pop("admin_fido_challenge", None)
    challenge = new_challenge()
    session["admin_fido_challenge"] = challenge

    fidos = Fido.filter_by(uuid=current_user.fido_uuid).all()
    webauthn_assertion_options = authentication_options(
        rp_id=RP_ID,
        challenge=challenge,
        credentials=[
            CredentialOption(fido.credential_id, fido.transports) for fido in fidos
        ],
        require_user_verification=True,
        hardware_hint=ADMIN_FIDO_REQUIRED == "hardware",
    )

    return render_template(
        "dashboard/enter_admin.html",
        fido_token_form=fido_token_form,
        webauthn_assertion_options=webauthn_assertion_options,
        next_url=next_url,
        hardware_required=ADMIN_FIDO_REQUIRED == "hardware",
    )
