import base64

import pytest
from flask import request, session
from saml2 import BINDING_HTTP_POST, saml
from saml2.s_utils import deflate_and_base64_encode
from werkzeug.exceptions import BadRequest

import flask_pysaml2 as auth
from tests.helpers import create_authn_request, unpack_form


class TestSamlHandleSSO:
    def test_handle_no_binding(self, flask_app, idp_config):
        with flask_app.test_request_context(
            "/",
            method="GET",
        ):
            idp = auth.SamlIdentityProvider(idp_config)
            with pytest.raises(BadRequest, match="Unable to find supported binding"):
                idp.handle_sso_request(request)

    def test_handle_no_authn_request(self, flask_app, idp_config):
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={
                "RelayState": "/next",
            },
        ):
            idp = auth.SamlIdentityProvider(idp_config)
            with pytest.raises(
                BadRequest, match="Unable to find SAMLRequest or SAMLResponse"
            ):
                idp.handle_sso_request(request)

    def test_handle_get(self, flask_app, idp_config, logged_in_identity):
        authn_request = create_authn_request(binding=BINDING_HTTP_POST)
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={
                "SAMLRequest": deflate_and_base64_encode(authn_request),
                "RelayState": "/next",
            },
        ):
            # first need to be logged in, let's pretend
            session["_saml_identity"] = logged_in_identity
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            idp = auth.SamlIdentityProvider(idp_config)
            resp = idp.handle_sso_request(request)
            assert resp.status_code == 200
            _form = unpack_form(resp.data.decode("utf-8"), ver="SAMLResponse")
            assert "SAMLResponse" in _form
            assert "RelayState" in _form

    def test_handle_post(self, flask_app, idp_post_config, logged_in_identity):
        authn_request = create_authn_request(binding=BINDING_HTTP_POST)
        with flask_app.test_request_context(
            "/",
            method="POST",
            data={
                "SAMLRequest": base64.b64encode(authn_request.encode("utf-8")),
                "RelayState": "/next",
            },
        ):
            # first need to be logged in, let's pretend
            session["_saml_identity"] = logged_in_identity
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            idp = auth.SamlIdentityProvider(idp_post_config)
            resp = idp.handle_sso_request(request)
            assert resp.status_code == 200
            _form = unpack_form(resp.data.decode("utf-8"), ver="SAMLResponse")
            assert "SAMLResponse" in _form
            assert "RelayState" in _form
