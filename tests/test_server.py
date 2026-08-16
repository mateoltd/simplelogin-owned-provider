from app.config import EMAIL_DOMAIN


def test_redirect_login_page(flask_client):
    """Start with a blank database."""

    rv = flask_client.get("/")
    assert rv.status_code == 302
    assert rv.location == f"http://{EMAIL_DOMAIN}/auth/login"


def test_real_app_preserves_multipart_part_limit_status(flask_client):
    boundary = "owned-provider-real-app"
    parts = []
    for index in range(1001):
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="part-{index}"'
            "\r\n\r\nx\r\n"
        )
    parts.append(f"--{boundary}--\r\n")

    response = flask_client.post(
        "/auth/login",
        data="".join(parts).encode(),
        content_type=f"multipart/form-data; boundary={boundary}",
    )

    assert response.status_code == 413
