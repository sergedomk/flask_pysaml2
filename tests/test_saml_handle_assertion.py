import base64

import pytest
from flask import request, session
from saml2.sigver import SignatureError
from werkzeug.exceptions import BadRequest

import flask_pysaml2 as auth
from tests.helpers import create_authn_response


class TestSamlHandleAssertion:
    def test_Saml_handle_assertion(self, flask_app, sp_config):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # create a response to assert upon
        _name_id, authn_response = create_authn_response(session_id, ava)
        assert b"Signature" in authn_response
        # test fails if there is no known outstanding auth request
        with flask_app.test_request_context(
            "/",
            method="POST",
            data={
                "SAMLResponse": base64.b64encode(authn_response),
                "RelayState": "/next",
            },
        ):
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(Exception):
                sp.handle_assertion(request)

    def test_Saml_handle_assertion_with_default_user_mappings(
        self, flask_app, sp_config
    ):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # create a response to assert upon
        name_id, authn_response = create_authn_response(session_id, ava)
        # test with default user_id mapping
        with flask_app.test_request_context(
            "/",
            method="POST",
            data={
                "SAMLResponse": base64.b64encode(authn_response),
                "RelayState": "/next",
            },
        ):
            # make the client thing there is outstanding request
            session["_saml_outstanding_queries"] = {session_id: "/next"}
            sp = auth.SamlServiceProvider(sp_config)
            user_attributes, resp = sp.handle_assertion(request)
            assert user_attributes["name_id"][0] == name_id
            assert user_attributes["uid"][0] == "123456"
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/next"
            # outstanding queury cache should now be empty
            assert session.get("_saml_outstanding_queries", {}) == {}
            # identity and subject_id should now be set
            assert session.get("_saml_subject_id").text == name_id

    @pytest.mark.skip(
        reason="Encryption in pysaml2 2.0.0 is possibly broken. If not, I don't know how to get it not blow up."
    )
    def test_Saml_handle_assertion_encrypted(self, flask_app, sp_config):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # create a response to assert upon
        _name_id, _authn_response = create_authn_response(
            session_id, ava, encrypt_assertion=True
        )

    def test_Saml_handle_assertion_allow_unsolicited_without_outstanding_queries(
        self, flask_app, sp_config
    ):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # The following setting allows for handling unsolicited
        # assertions which ironically is the expected behavior according to
        # the SAML 2.0 specification
        sp_config["service"]["sp"]["allow_unsolicited"] = "true"
        # create a response to assert upon
        name_id, authn_response = create_authn_response(session_id, ava)
        assert b"Signature" in authn_response
        # test success if no outstanding queries exist
        with flask_app.test_request_context(
            "/",
            method="POST",
            data={
                "SAMLResponse": base64.b64encode(authn_response),
                "RelayState": "/next",
            },
        ):
            sp = auth.SamlServiceProvider(sp_config)
            user_attributes, resp = sp.handle_assertion(request)
            assert user_attributes["name_id"][0] == name_id
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/next"
            # identity and subject_id should now be set
            assert name_id in next(iter(session.get("_saml_identity", {}).keys()))
            assert session.get("_saml_subject_id").text == name_id

    def test_Saml_handle_assertion_allow_unsolicited_with_outstanding_queries(
        self, flask_app, sp_config
    ):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # The following setting allows for handling unsolicited
        # assertions which ironically is the expected behavior according to
        # the SAML 2.0 specification
        sp_config["service"]["sp"]["allow_unsolicited"] = "true"
        # create a response to assert upon
        name_id, authn_response = create_authn_response(session_id, ava)
        # test success if outstanding queries exist
        with flask_app.test_request_context(
            "/",
            method="POST",
            data={
                "SAMLResponse": base64.b64encode(authn_response),
                "RelayState": "/next",
            },
        ):
            sp = auth.SamlServiceProvider(sp_config)
            session["_saml_outstanding_queries"] = {session_id: "/next"}
            user_attributes, resp = sp.handle_assertion(request)
            assert user_attributes["name_id"][0] == name_id
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/next"
            # outstanding queury cache should now be empty
            assert session.get("_saml_outstanding_queries", {}) == {}
            # identity and subject_id should now be set
            assert name_id in next(iter(session.get("_saml_identity", {}).keys()))
            assert session.get("_saml_subject_id").text == name_id

    def test_Saml_handle_assertion_missing_SAMLResponse(self, flask_app, sp_config):
        # test missing SAMLResponse
        with flask_app.test_request_context("/", method="POST"):
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_assertion(request)
            assert 400 == exc_info.value.code
            assert "SAMLResponse missing from POST" == exc_info.value.description

    def test_Saml_handle_assertion_invalid_SAMLResponse_get(self, flask_app, sp_config):
        # test SAMLResponse via GET
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={"SAMLResponse": "invalid", "RelayState": "/next"},
        ):
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_assertion(request)
            assert 400 == exc_info.value.code
            assert "SAMLResponse missing from POST" == exc_info.value.description

    def test_Saml_handle_assertion_invalid_SAMLResponse_post(
        self, flask_app, sp_config
    ):
        # test invalid SAMLResponse
        with flask_app.test_request_context(
            "/", method="POST", data={"SAMLResponse": "invalid", "RelayState": "/next"}
        ):
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_assertion(request)
            assert 400 == exc_info.value.code
            assert "SAML response is invalid" == exc_info.value.description

    def test_Saml_handle_assertion_invalid_SAMLResponse_signing_required(
        self, flask_app, sp_config
    ):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # test on unsigned SAMLResponse when signing is required
        # create a response to assert upon
        _name_id, authn_response = create_authn_response(
            session_id, ava, sign_response=False, sign_assertion=False
        )
        assert b"Signature" not in authn_response
        with flask_app.test_request_context(
            "/",
            method="POST",
            data={
                "SAMLResponse": base64.b64encode(authn_response),
                "RelayState": "/next",
            },
        ):
            sp = auth.SamlServiceProvider(sp_config)
            # test fails if there is no known outstanding auth request
            with pytest.raises(Exception):
                sp.handle_assertion(request)
            # make the client thing there is outstanding request
            session["_saml_outstanding_queries"] = {session_id: "/next"}
            # test fails if there is not a missing signature
            with pytest.raises(SignatureError, match="Signature missing for response"):
                _user_attributes, _resp = sp.handle_assertion(request)
