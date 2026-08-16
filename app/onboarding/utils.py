from dataclasses import dataclass
from enum import Enum
from flask import request
from typing import Optional

CHROME_EXTENSION_LINK = "https://chrome.google.com/webstore/detail/simpleloginreceive-send-e/dphilobhebphkdjbpfohgikllaljmgbn"
FIREFOX_EXTENSION_LINK = "https://addons.mozilla.org/firefox/addon/simplelogin/"
EDGE_EXTENSION_LINK = "https://microsoftedge.microsoft.com/addons/detail/simpleloginreceive-sen/diacfpipniklenphgljfkmhinphjlfff"


@dataclass
class ExtensionInfo:
    browser: str
    url: str


class Browser(Enum):
    Firefox = 1
    Chrome = 2
    Edge = 3
    Other = 4


def browser_from_user_agent(user_agent: str) -> Browser:
    """Classify only browsers for which an extension is offered.

    Werkzeug 3 deliberately stopped parsing user-agent strings. Keep this
    small decision table local instead of adding a second parser dependency.
    Mobile agents are excluded even when their strings contain a desktop
    browser token.
    """
    normalized = user_agent.casefold()
    if any(
        token in normalized
        for token in ("android", "blackberry", "ipad", "iphone", "symbian")
    ):
        return Browser.Other
    if "edg/" in normalized or "edge/" in normalized:
        return Browser.Edge
    if "firefox/" in normalized or "fxios/" in normalized:
        return Browser.Firefox
    if any(token in normalized for token in ("chrome/", "chromium/", "opr/")):
        return Browser.Chrome
    return Browser.Other


def get_browser() -> Browser:
    return browser_from_user_agent(request.headers.get("User-Agent", ""))


def get_extension_info() -> Optional[ExtensionInfo]:
    browser = get_browser()
    if browser == Browser.Chrome:
        extension_link = CHROME_EXTENSION_LINK
        browser_name = "Chrome"
    elif browser == Browser.Firefox:
        extension_link = FIREFOX_EXTENSION_LINK
        browser_name = "Firefox"
    elif browser == Browser.Edge:
        extension_link = EDGE_EXTENSION_LINK
        browser_name = "Edge"
    else:
        return None
    return ExtensionInfo(
        browser=browser_name,
        url=extension_link,
    )
