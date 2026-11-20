from flask import Flask, request
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
            "idp": ["https://sso.example.com/idp/metadata"],
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
                "entityid": "https://sso.example.com/idp/metadata",
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
                                    "https://sso.example.com/idp/sso",
                                    BINDING_HTTP_REDIRECT,
                                )
                            ],
                            "single_logout_service": [
                                (
                                    "https://sso.example.com/idp/slo",
                                    BINDING_HTTP_REDIRECT,
                                )
                            ],
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
idp = flask_pysaml2.SamlIdentityProvider(CONFIG)


@app.route("/idp/sso")
def idp_sso():
    return idp.handle_sso_request(request)


@app.route("/sp/metadata", methods=["GET"])
def idp_metadata():
    return idp.get_metadata()


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


if __name__ == "__main__":
    # requires pyopenssl for adhoc ssl_context: `pip install pyopenssl`
    app.run(debug=True, host="127.0.0.1", port=5001, ssl_context="adhoc")
