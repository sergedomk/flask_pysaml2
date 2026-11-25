from flask import Flask, request
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from saml2 import BINDING_HTTP_REDIRECT

import flask_pysaml2

# The config is a pysaml2 config (https://pysaml2.readthedocs.io/en/latest/howto/config.html).
CONFIG = {
    "entityid": "https://127.0.0.1:5000/sp/metadata",
    "contact_person": [
        {
            "given_name": "John",
            "sur_name": "Smith",
            "email_address": "john.smith@foo.example.com",
            "type": "technical",
        }
    ],
    "service": {
        "sp": {
            "name": "Test Service Provider",
            "endpoints": {
                "assertion_consumer_service": ["https://127.0.0.1:5000/sp/acs"],
                "single_logout_service": [
                    ("https://127.0.0.1:5000/sp/slo", BINDING_HTTP_REDIRECT)
                ],
            },
            "idp": ["https://127.0.0.1:5001/idp/metadata"],
            "logout_requests_signed": True,
            "authn_requests_signed": True,
            "want_response_signed": False,
            "want_assertion_signed": True,
        },
    },
    "debug": True,
    "xmlsec_binary": "/usr/bin/xmlsec1",
    "key_file": "<replace with full path to sso private key>",
    "cert_file": "<replace with full path to sso public certificate>",
    "ca_certs": None,
    "metadata": {
        # We added `inline_dict` as a means to dynamically configure IDPs.
        #
        # You'll want to replace the below with the attributes for the IDP
        # you'll be connecting with.
        "inline_dict": [
            {
                "entityid": "https://127.0.0.1:5001/idp/metadata",
                "contact_person": [
                    {
                        "email_address": "helpdesk@kavi.com",
                        "contact_type": "technical",
                    },
                ],
                "service": {
                    "idp": {
                        "name": "Test Identity Provider",
                        "endpoints": {
                            "single_sign_on_service": [
                                (
                                    "https://127.0.0.1:5001/idp/sso",
                                    BINDING_HTTP_REDIRECT,
                                )
                            ],
                            # "single_logout_service": [
                            #     (
                            #         "https://127.0.0.1:5001/idp/slo",
                            #         BINDING_HTTP_REDIRECT,
                            #     )
                            # ],
                        },
                        "policy": {
                            "default": {
                                "lifetime": {"hours": 24},
                                "attribute_restrictions": None,
                                "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                            },
                        },
                    },
                },
                "cert_file": "<replace with full path to IPD public certificate>",
            }
        ],
    },
}

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "sp_login"

sp = flask_pysaml2.SamlServiceProvider(CONFIG)


class User(UserMixin):
    id: int

    def __init__(self, id):
        super().__init__()
        self.id = id


@login_manager.user_loader
def load_user(user_id):
    # Load the user.
    return User(user_id)


@app.route("/sp/login")
def sp_login():
    return sp.authenticate(next_url="/")


@app.route("/sp/logout")
@login_required
def sp_logout():
    logout_user()  # Perform local logout.
    return sp.logout(next_url="/")


@app.route("/sp/acs", methods=["GET", "POST"])
def sp_acs():
    _assertion_info, redirect = sp.handle_assertion(request)
    # Retrieve the user.
    user = User(_assertion_info["uid"][0])
    # Log in the user.
    login_user(user)
    return redirect


@app.route("/sp/slo", methods=["GET", "POST"])
def sp_slo():
    logout_user()  # Perform local logout
    # Note: slo can fail below leaving the user logged in elsewhere.
    _success, redirect = sp.handle_logout(request, next_url="/")
    return redirect


@app.route("/sp/metadata", methods=["GET"])
def sp_metadata():
    return sp.get_metadata()


@app.route("/")
@login_required
def hello_world():
    return "<p>Hello, World!</p>"


if __name__ == "__main__":
    # requires flask-login for login logic: `pip install flask-login`
    # requires pyopenssl for adhoc ssl_context: `pip install pyopenssl`
    app.run(debug=True, host="127.0.0.1", port=5000, ssl_context="adhoc")
