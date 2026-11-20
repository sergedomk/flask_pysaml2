import copy

import pytest
from flask import Flask

from .idp_config import CONFIG as ORIG_IDP_CONFIG
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
