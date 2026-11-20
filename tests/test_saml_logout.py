import time

import pytest
from flask import session
from saml2 import saml, samlp
from saml2.s_utils import decode_base64_and_inflate

import flask_pysaml2 as auth
from tests.helpers import ROOT_PATH, parse_location_header, unpack_form


class TestSamlLogout:
    @pytest.fixture
    def identity_get(self):
        not_on_or_after = int(time.time()) + 3600
        return {
            "4=id-1": {
                "https://sso.example.com/idp/metadata": (
                    not_on_or_after,
                    {
                        "authn_info": [],
                        "name_id": "id-1",
                        "not_on_or_after": not_on_or_after,
                        "came_from": "/next",
                        "ava": {"uid": ["123456"]},
                    },
                )
            }
        }

    @pytest.fixture
    def identity_post(self):
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

    def test_Saml_logout_signed(self, flask_app, sp_config, identity_get):
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.SamlServiceProvider(sp_config)
            # first need to be logged in, let's pretend
            session["_saml_identity"] = identity_get
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            resp = sp.logout(next_url="/next")
            assert resp.status_code == 302
            assert "SAMLRequest" in resp.headers["Location"]
            url, params = parse_location_header(resp.headers["Location"])
            assert url.hostname == "sso.example.com"
            assert url.path == "/idp/slo"
            assert "Signature" in params
            assert "SigAlg" in params
            assert "SAMLRequest" in params
            logout = samlp.logout_request_from_string(
                decode_base64_and_inflate(params["SAMLRequest"][0])
            )
            assert logout.destination == "https://sso.example.com/idp/slo"
            assert logout.name_id.text == "id-1"
            # check the caches still contain data
            assert session["_saml_identity"] == identity_get
            assert session["_saml_subject_id"].text == "id-1"
            # verify state cache
            assert logout.id in session["_saml_state"]
            assert (
                session["_saml_state"][logout.id]["entity_id"]
                == "https://sso.example.com/idp/metadata"
            )
            assert session["_saml_state"][logout.id]["entity_ids"] == [
                "https://sso.example.com/idp/metadata"
            ]
            assert session["_saml_state"][logout.id]["operation"] == "SLO"
            # name_id is now being coded/decoded
            assert session["_saml_state"][logout.id]["name_id"] == "4=id-1"
            assert session["_saml_state"][logout.id]["reason"] == ""
            assert session["_saml_state"][logout.id]["sign"] is True

    def test_Saml_logout_unsigned(self, flask_app, sp_config, identity_get):
        # test unsigned logout request
        with flask_app.test_request_context("/", method="GET"):
            sp_config["service"]["sp"]["logout_requests_signed"] = False
            sp = auth.SamlServiceProvider(sp_config)
            # first need to be logged in, let's pretend
            session["_saml_identity"] = identity_get
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            resp = sp.logout(next_url="/next")
            assert resp.status_code == 302
            assert "SAMLRequest" in resp.headers["Location"]
            _url, params = parse_location_header(resp.headers["Location"])
            assert "SAMLRequest" in params
            logout = samlp.logout_request_from_string(
                decode_base64_and_inflate(params["SAMLRequest"][0])
            )
            assert logout.signature is None
            # verify state cache shows signing off
            assert session["_saml_state"][logout.id]["sign"] is False

    def test_Saml_logout_via_post(self, flask_app, sp_config, identity_post):
        # test signed authentication request
        with flask_app.test_request_context("/", method="GET"):
            sp_config["metadata"] = {"local": [ROOT_PATH + "/idp_post_metadata.xml"]}
            sp = auth.SamlServiceProvider(sp_config)
            # first need to be logged in, let's pretend
            session["_saml_identity"] = identity_post
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            resp, status = sp.logout(next_url="/next")
            assert status == 200
            _form = unpack_form(resp["data"][3])
            assert "SAMLRequest" in _form
            assert "RelayState" in _form

    def test_Saml_logout_not_logged_in(self, flask_app, sp_config):
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(
                auth.AuthException, match="Unable to retrieve subject id for logout"
            ):
                sp.logout(next_url="/next")

    def test_Saml_logout_required_missing_key_file(
        self, flask_app, sp_config, identity_get
    ):
        with flask_app.test_request_context("/", method="GET"):
            sp_config["key_file"] = None
            sp = auth.SamlServiceProvider(sp_config)
            # first need to be logged in, let's pretend
            session["_saml_identity"] = identity_get
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            with pytest.raises(
                auth.AuthException,
                match="Signature requested for this Saml logout request, but no private key file configured",
            ):
                sp.logout(next_url="/next")
