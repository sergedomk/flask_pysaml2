import copy
import time

import pytest
from flask import Flask
from saml2 import saml

from .idp_config import CONFIG as ORIG_IDP_CONFIG
from .idp_post_config import CONFIG as ORIG_IDP_POST_CONFIG
from .sp_config import CONFIG as ORIG_SP_CONFIG

SUPER_SECRET_KEY = "Super secret key. Shhhh!"


@pytest.fixture
def flask_app():
    app = Flask(__name__)
    app.secret_key = SUPER_SECRET_KEY
    return app


@pytest.fixture
def sp_config():
    # many tests modify config, make copy so one test doesn't affect other tests.
    return copy.deepcopy(ORIG_SP_CONFIG)


@pytest.fixture
def idp_config():
    # many tests modify config, make copy so one test doesn't affect other tests.
    return copy.deepcopy(ORIG_IDP_CONFIG)


@pytest.fixture
def idp_post_config():
    # many tests modify config, make copy so one test doesn't affect other tests.
    return copy.deepcopy(ORIG_IDP_POST_CONFIG)


@pytest.fixture
def logged_in_identity():
    not_on_or_after = int(time.time()) + 3600
    return {
        "4=id-1": {
            "https://sso.example.com/idp/metadata": (
                not_on_or_after,
                {
                    "authn_info": [
                        ("urn:oasis:names:tc:SAML:2.0:ac:classes:Password", [])
                    ],
                    "name_id": saml.NameID(text="id-1"),
                    "not_on_or_after": not_on_or_after,
                    "came_from": "/next",
                    "ava": {"uid": ["a123456"]},
                },
            )
        }
    }
