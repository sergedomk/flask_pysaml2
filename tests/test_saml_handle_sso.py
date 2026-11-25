import base64

import pytest
from flask import request, session
from saml2 import BINDING_HTTP_POST, samlp
from saml2.response import IncorrectlySigned
from saml2.s_utils import deflate_and_base64_encode
from saml2.xmldsig import SIG_RSA_SHA1
from werkzeug.exceptions import BadRequest

import flask_pysaml2 as auth
from tests.helpers import (
    create_authn_request,
    get_signature_for_authn_request,
    unpack_form,
)


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
            session["_saml_subject_id"] = "4=id-1"
            idp = auth.SamlIdentityProvider(idp_config)
            resp = idp.handle_sso_request(request)
            assert resp.status_code == 200
            _form = unpack_form(resp.data.decode("utf-8"), ver="SAMLResponse")
            assert "SAMLResponse" in _form
            assert "RelayState" in _form
            resp_obj = samlp.response_from_string(
                base64.b64decode(_form["SAMLResponse"])
            )
            assert resp_obj.destination == "https://foo.example.com/sp/acs"
            assert (
                resp_obj.assertion[0].attribute_statement[0].attribute[0].name_format
                == "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
            )
            assert (
                resp_obj.assertion[0]
                .attribute_statement[0]
                .attribute[0]
                .attribute_value[0]
                .text
                == "a123456"
            )

    def test_handle_get_signed(self, flask_app, idp_config, logged_in_identity):
        authn_request = create_authn_request(binding=BINDING_HTTP_POST)
        encoded_authn_request = deflate_and_base64_encode(authn_request)
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={
                "SAMLRequest": encoded_authn_request,
                "SigAlg": SIG_RSA_SHA1,
                "Signature": get_signature_for_authn_request(
                    encoded_authn_request, SIG_RSA_SHA1
                ),
            },
        ):
            # first need to be logged in, let's pretend
            session["_saml_identity"] = logged_in_identity
            session["_saml_subject_id"] = "4=id-1"
            idp_config["service"]["idp"]["want_authn_requests_signed"] = True
            idp = auth.SamlIdentityProvider(idp_config)
            resp = idp.handle_sso_request(request)
            assert resp.status_code == 200

    def test_handle_get_missing_signature(self, flask_app, idp_config):
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
            idp_config["service"]["idp"]["want_authn_requests_signed"] = True
            idp = auth.SamlIdentityProvider(idp_config)
            with pytest.raises(
                IncorrectlySigned, match="Request was not signed correctly"
            ):
                idp.handle_sso_request(request)

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
            session["_saml_subject_id"] = "4=id-1"
            idp = auth.SamlIdentityProvider(idp_post_config)
            resp = idp.handle_sso_request(request)
            assert resp.status_code == 200
            _form = unpack_form(resp.data.decode("utf-8"), ver="SAMLResponse")
            assert "SAMLResponse" in _form
            assert "RelayState" in _form

    def test_handle_post_signed(self, flask_app, idp_post_config, logged_in_identity):
        authn_request = create_authn_request(binding=BINDING_HTTP_POST, sign_post=True)
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
            session["_saml_subject_id"] = "4=id-1"
            idp_post_config["service"]["idp"]["want_authn_requests_signed"] = True
            idp = auth.SamlIdentityProvider(idp_post_config)
            resp = idp.handle_sso_request(request)
            assert resp.status_code == 200

    def test_handle_post_missing_signature(self, flask_app, idp_post_config):
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
            idp_post_config["service"]["idp"]["want_authn_requests_signed"] = True
            idp = auth.SamlIdentityProvider(idp_post_config)
            with pytest.raises(
                IncorrectlySigned, match="Request was not signed correctly"
            ):
                idp.handle_sso_request(request)
