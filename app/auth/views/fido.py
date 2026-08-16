import json
import uuid

from flask import (
    request,
    render_template,
    redirect,
    url_for,
    flash,
    session,
    make_response,
    g,
)
from flask_login import login_user
from flask_wtf import FlaskForm
from time import time
from wtforms import HiddenField, validators, BooleanField

from app.auth.base import auth_bp
from app.config import MFA_USER_ID
from app.config import RP_ID, URL
from app.db import Session
from app.extensions import limiter
from app.log import LOG
from app.models import User, Fido, MfaBrowser
from app.utils import sanitize_next_url
from app.webauthn_utils import (
    CredentialOption,
    authentication_options,
    new_challenge,
    verify_authentication,
)


class FidoTokenForm(FlaskForm):
    sk_assertion = HiddenField("sk_assertion", validators=[validators.DataRequired()])
    remember = BooleanField(
        "attr", default=False, description="Remember this browser for 30 days"
    )


@auth_bp.route("/fido", methods=["GET", "POST"])
@limiter.limit(
    "10/minute", deduct_when=lambda r: hasattr(g, "deduct_limit") and g.deduct_limit
)
def fido():
    # passed from login page
    user_id = session.get(MFA_USER_ID)

    # user access this page directly without passing by login page
    if not user_id:
        flash("Unknown error, redirect back to main page", "warning")
        return redirect(url_for("auth.login"))

    user = User.get(user_id)

    if not (user and user.fido_enabled()):
        flash("Only user with security key linked should go to this page", "warning")
        return redirect(url_for("auth.login"))

    auto_activate = True
    fido_token_form = FidoTokenForm()

    next_url = sanitize_next_url(request.args.get("next"))

    if request.cookies.get("mfa"):
        browser = MfaBrowser.get_by(token=request.cookies.get("mfa"))
        if browser and not browser.is_expired() and browser.user_id == user.id:
            # Rotate session ID to prevent session fixation
            session.session_id = str(uuid.uuid4())
            login_user(user)
            flash("Welcome back!", "success")
            # Redirect user to correct page
            return redirect(next_url or url_for("dashboard.index"))
        else:
            # Trigger rate limiter
            g.deduct_limit = True

    # Handling POST requests
    if fido_token_form.validate_on_submit():
        challenge = session.pop("fido_challenge", None)
        if not challenge:
            flash("Session expired. Please try again.", "warning")
            g.deduct_limit = True
            return redirect(url_for("auth.login"))
        try:
            sk_assertion = json.loads(fido_token_form.sk_assertion.data)
        except Exception:
            flash("Key verification failed. Error: Invalid Payload", "warning")
            return redirect(url_for("auth.login"))

        try:
            fido_key = Fido.get_by(
                uuid=user.fido_uuid, credential_id=sk_assertion["id"]
            )
            if not fido_key:
                raise ValueError("Unknown WebAuthn credential")
            new_sign_count = verify_authentication(
                credential=sk_assertion,
                challenge=challenge,
                rp_id=RP_ID,
                origin=URL,
                credential_id=fido_key.credential_id,
                public_key=fido_key.public_key,
                current_sign_count=fido_key.sign_count,
            )
        except Exception as e:
            LOG.w(f"An error occurred in WebAuthn verification process: {e}")
            flash("Key verification failed.", "warning")
            # Trigger rate limiter
            g.deduct_limit = True
            auto_activate = False
        else:
            fido_key.sign_count = new_sign_count
            Session.commit()
            del session[MFA_USER_ID]

            session["sudo_time"] = int(time())
            # Rotate session ID to prevent session fixation
            session.session_id = str(uuid.uuid4())
            login_user(user)
            flash("Welcome back!", "success")

            # Redirect user to correct page
            response = make_response(redirect(next_url or url_for("dashboard.index")))

            if fido_token_form.remember.data:
                browser = MfaBrowser.create_new(user=user)
                Session.commit()
                response.set_cookie(
                    "mfa",
                    value=browser.token,
                    expires=browser.expires.datetime,
                    secure=True if URL.startswith("https") else False,
                    httponly=True,
                    samesite="Lax",
                )

            return response

    # Prepare information for key registration process
    session.pop("challenge", None)
    challenge = new_challenge()

    session["fido_challenge"] = challenge

    fidos = Fido.filter_by(uuid=user.fido_uuid).all()
    webauthn_assertion_options = authentication_options(
        rp_id=RP_ID,
        challenge=challenge,
        credentials=[
            CredentialOption(fido.credential_id, fido.transports) for fido in fidos
        ],
    )

    return render_template(
        "auth/fido.html",
        fido_token_form=fido_token_form,
        webauthn_assertion_options=webauthn_assertion_options,
        enable_otp=user.enable_otp,
        auto_activate=auto_activate,
        next_url=next_url,
    )
