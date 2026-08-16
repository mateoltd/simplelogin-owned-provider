from http import HTTPStatus
import pytest

from app.onboarding.utils import (
    Browser,
    CHROME_EXTENSION_LINK,
    browser_from_user_agent,
)

CHROME_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"


@pytest.mark.parametrize(
    ("user_agent", "expected"),
    [
        (CHROME_USER_AGENT, Browser.Chrome),
        ("Mozilla/5.0 Firefox/128.0", Browser.Firefox),
        ("Mozilla/5.0 Edg/128.0", Browser.Edge),
        ("Mozilla/5.0 OPR/112.0", Browser.Chrome),
        ("Mozilla/5.0 (iPhone) CriOS/128.0 Mobile", Browser.Other),
        ("curl/8.10.0", Browser.Other),
    ],
)
def test_browser_from_user_agent(user_agent, expected):
    assert browser_from_user_agent(user_agent) is expected


def test_extension_redirect_is_working(flask_client):
    res = flask_client.get(
        "/onboarding/extension_redirect", headers={"User-Agent": CHROME_USER_AGENT}
    )
    assert res.status_code == HTTPStatus.FOUND

    location_header = res.headers.get("Location")
    assert location_header == CHROME_EXTENSION_LINK
