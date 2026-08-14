from __future__ import annotations

from flask import Blueprint, jsonify
from sqlalchemy import text

from app.db import Session

from .composition import MailEdgeBridge


def create_mail_edge_health_blueprint(bridge: MailEdgeBridge) -> Blueprint:
    blueprint = Blueprint("mail_edge_health", __name__)

    @blueprint.route("/health/mail-edge/livez", methods=["GET"])
    def live():
        return jsonify({"status": "live"}), 200

    @blueprint.route("/health/mail-edge/readyz", methods=["GET"])
    def ready():
        database_ready = False
        edge_ready = False
        host_delivery_ready = bridge.host_admission.ready()
        try:
            Session.execute(text("SELECT 1"))
            database_ready = True
            edge_ready = bridge.client.ready()
        except Exception:
            Session.rollback()
        ready_now = database_ready and edge_ready and host_delivery_ready
        return (
            jsonify(
                {
                    "status": "ready" if ready_now else "not_ready",
                    "checks": {
                        "database": database_ready,
                        "hostDelivery": host_delivery_ready,
                        "mailEdge": edge_ready,
                    },
                }
            ),
            200 if ready_now else 503,
        )

    return blueprint
