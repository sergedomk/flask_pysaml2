from flask import Flask, request
from saml2 import BINDING_HTTP_REDIRECT

import flask_pysaml2

# The config is a pysaml2 config (https://pysaml2.readthedocs.io/en/latest/howto/config.html).
CONFIG = {
    "entityid": "https://127.0.0.1:5001/idp/metadata",
    "contact_person": [
        {
            "given_name": "John",
            "sur_name": "Smith",
            "email_address": "john.smith@foo.example.com",
            "type": "technical",
        }
    ],
    "service": {
        "idp": {
            "name": "Test Identity Provider",
            "endpoints": {
                "single_sign_on_service": [
                    ("https://127.0.0.1:5001/idp/sso", BINDING_HTTP_REDIRECT)
                ],
                # "single_logout_service": [
                #     ("https://127.0.0.1:5001/idp/slo", BINDING_HTTP_REDIRECT)
                # ],
            },
            "policy": {
                "default": {
                    "lifetime": {"hours": 24},
                    "attribute_restrictions": None,
                    "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                },
            },
        }
    },
    "debug": True,
    "xmlsec_binary": "/usr/bin/xmlsec1",
    "key_file": "<replace with full path to sso private key>",
    "cert_file": "<replace with full path to sso public certificate>",
    "ca_certs": None,
    "metadata": {
        "inline_dict": [
            {
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
                            "assertion_consumer_service": [
                                "https://127.0.0.1:5000/sp/acs"
                            ],
                            "single_logout_service": [
                                ("https://127.0.0.1:5000/sp/slo", BINDING_HTTP_REDIRECT)
                            ],
                        },
                    },
                },
                "cert_file": "<replace with full path to sso public certificate>",
            }
        ],
    },
}

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY"

idp = flask_pysaml2.SamlIdentityProvider(CONFIG)


@app.route("/idp/sso")
def idp_sso():
    idp.set_subject_id_in_session("4=id-1")
    idp.add_user_identity(
        subject_id=idp.subject_id_from_session,
        session_info={"uid": ["a123456"], "ava": {"uid": ["a123456"]}},
    )
    response = idp.handle_sso_request(request)

    return response


@app.route("/idp/metadata", methods=["GET"])
def idp_metadata():
    return idp.get_metadata()


if __name__ == "__main__":
    # requires pyopenssl for adhoc ssl_context: `pip install pyopenssl`
    app.run(debug=True, host="127.0.0.1", port=5001, ssl_context="adhoc")
