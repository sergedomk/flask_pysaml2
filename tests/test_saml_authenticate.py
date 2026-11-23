import pytest
from flask import session
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, samlp
from saml2.s_utils import UnsupportedBinding, decode_base64_and_inflate

import flask_pysaml2 as auth
from tests.helpers import ROOT_PATH, parse_location_header, unpack_form


class TestSamlAuthenticate:
    def test_authenticate(self, flask_app, sp_config):
        # test signed authentication request
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.SamlServiceProvider(sp_config)
            resp = sp.authenticate(next_url="/next")
            assert resp.status_code == 302
            assert "SAMLRequest" in resp.headers["Location"]
            url, params = parse_location_header(resp.headers["Location"])
            assert url.hostname == "sso.example.com"
            assert url.path == "/idp/sso"
            assert "SAMLRequest" in params
            assert "Signature" in params
            assert params["RelayState"] == ["/next"]
            authn = samlp.authn_request_from_string(
                decode_base64_and_inflate(params["SAMLRequest"][0])
            )
            assert authn.destination == "https://sso.example.com/idp/sso"
            assert (
                authn.assertion_consumer_service_url == "https://foo.example.com/sp/acs"
            )
            assert authn.protocol_binding == BINDING_HTTP_POST
            assert session["_saml_outstanding_queries"] == {authn.id: "/next"}

    def test_authenticate_unsigned(self, flask_app, sp_config):
        # test un-signed authentication request
        with flask_app.test_request_context("/", method="GET"):
            sp_config["service"]["sp"]["authn_requests_signed"] = None
            sp = auth.SamlServiceProvider(sp_config)
            resp = sp.authenticate(next_url="/next")
            assert resp.status_code == 302
            _, params = parse_location_header(resp.headers["Location"])
            assert "SAMLRequest" in params
            assert "Signature" not in params

    def test_authenticate_via_post(self, flask_app, sp_config):
        # test signed authentication request
        with flask_app.test_request_context("/", method="GET"):
            sp_config["metadata"] = {"local": [ROOT_PATH + "/idp_post_metadata.xml"]}
            sp = auth.SamlServiceProvider(sp_config)
            resp, status = sp.authenticate(next_url="/next", binding=BINDING_HTTP_POST)
            assert status == 200
            _form = unpack_form(resp["data"][3])
            assert "SAMLRequest" in _form
            assert "RelayState" in _form
            authn_id = next(iter(session["_saml_outstanding_queries"].keys()))
            assert session["_saml_outstanding_queries"] == {authn_id: "/next"}

    def test_authenticate_no_idp_configured(self, flask_app, sp_config):
        # test using binding method not configured for in IdP metadata
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(
                UnsupportedBinding,
                match="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            ):
                sp.authenticate(next_url="/next", binding=BINDING_HTTP_POST)

    def test_authenticate_no_idp_allowed(self, flask_app, sp_config):
        # test with only allowed IdP not included in metadata file
        with flask_app.test_request_context("/", method="GET"):
            sp_config["metadata"] = {}
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(
                auth.AuthException, match="Unable to locate valid IdP for this request"
            ):
                sp.authenticate(next_url="/next")

    def test_authenticate_multiple_idps(self, flask_app, sp_config):
        entity_id = "https://sso-alt.example.com/idp/metadata"
        sp_config["metadata"]["inline_dict"] = [
            {
                "entityid": entity_id,
                "service": {
                    "idp": {
                        "name": "Test Identity Provider",
                        "endpoints": {
                            "single_sign_on_service": [
                                (
                                    "https://sso-alt.example.com/idp/sso",
                                    BINDING_HTTP_REDIRECT,
                                )
                            ],
                            "single_logout_service": [
                                (
                                    "https://sso-alt.example.com/idp/slo",
                                    BINDING_HTTP_REDIRECT,
                                )
                            ],
                        },
                    },
                },
                "cert_file": ROOT_PATH + "/sso_public.crt",
            }
        ]
        # Remove default idp form SP config.
        del sp_config["service"]["sp"]["idp"]
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.SamlServiceProvider(sp_config)
            assert None == sp._config.getattr("idp")
            resp = sp.authenticate(next_url="/next")
            assert resp.status_code == 302
            url, params = parse_location_header(resp.headers["Location"])
            assert url.hostname == "ds.example.com"
            assert url.path == "/disco"
            assert sp_config["entityid"] == params["entityID"][0]
            assert (
                "https://foo.example.com/sp/disco_resp?session_id="
                == params["return"][0][:49]
            )

    def test_authenticate_multiple_idps_with_idp_default(self, flask_app, sp_config):
        entity_id = "https://sso-alt.example.com/idp/metadata"
        sp_config["metadata"]["inline_dict"] = [
            {
                "entityid": entity_id,
                "service": {
                    "idp": {
                        "name": "Test Identity Provider",
                        "endpoints": {
                            "single_sign_on_service": [
                                (
                                    "https://sso-alt.example.com/idp/sso",
                                    BINDING_HTTP_REDIRECT,
                                )
                            ],
                            "single_logout_service": [
                                (
                                    "https://sso-alt.example.com/idp/slo",
                                    BINDING_HTTP_REDIRECT,
                                )
                            ],
                        },
                    },
                },
                "cert_file": ROOT_PATH + "/sso_public.crt",
            }
        ]
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.SamlServiceProvider(sp_config)
            resp = sp.authenticate(next_url="/next")
            assert resp.status_code == 302
            assert "SAMLRequest" in resp.headers["Location"]
            url, params = parse_location_header(resp.headers["Location"])
            assert url.hostname == "sso.example.com"
            assert url.path == "/idp/sso"
            assert "SAMLRequest" in params
            assert params["RelayState"] == ["/next"]

    def test_authenticate_required_missing_key_file(self, flask_app, sp_config):
        # test signed authentication request w/o private key file
        with flask_app.test_request_context("/", method="GET"):
            sp_config["key_file"] = None
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(
                auth.AuthException,
                match="Signature requested for this Saml authentication request, but no private key file configured",
            ):
                sp.authenticate(next_url="/next")
            # outstanding queury cache should still be empty
            assert session.get("_saml_outstanding_queries", {}) == {}
