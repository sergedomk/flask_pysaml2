import base64
import time

import pytest
from flask import request, session
from saml2 import BINDING_HTTP_POST, saml, samlp
from saml2.ident import code
from saml2.s_utils import decode_base64_and_inflate, deflate_and_base64_encode
from werkzeug.exceptions import BadRequest

import flask_pysaml2 as auth
from tests.helpers import (
    create_logout_request,
    create_logout_response,
    parse_location_header,
)


class TestSamlHandleLogout:
    @pytest.fixture
    def resp_session_data(self):
        not_on_or_after = int(time.time()) + 3600
        identity = {
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
        state = {
            "entity_ids": ["https://sso.example.com/idp/metadata"],
            "subject_id": "id-1",
            #'return_to': '/next',
            "name_id": "4=id-1",
            "entity_id": "https://sso.example.com/idp/metadata",
            "not_on_or_after": not_on_or_after,
            "operation": "SLO",
            "reason": "",
        }
        return identity, state

    @pytest.fixture
    def req_session_data(self, logged_in_identity):
        entity_id = "https://sso.example.com/idp/metadata"
        state = {
            "entity_ids": [entity_id],
            "name_id": "4=id-1",
            "entity_id": entity_id,
            "not_on_or_after": logged_in_identity["4=id-1"][entity_id][0],
            "operation": "SLO",
            "reason": "",
            "sign": False,
        }
        return logged_in_identity, state

    def test_Saml_handle_logout_response_get(
        self, flask_app, sp_config, resp_session_data
    ):
        # create a response to assert upon
        sp = auth.SamlServiceProvider(sp_config)
        session_id, logout_response = create_logout_response(
            "id-1",
            destination="https://sso.example.com/idp/slo",
            issuer_entity_id="https://sso.example.com/idp/metadata",
            req_entity_id="https://foo.example.com/sp/metadata",
        )
        assert b"Signature" in logout_response
        # test SAMLResponse logout as GET
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={
                "SAMLResponse": deflate_and_base64_encode(logout_response),
                "RelayState": "/next",
            },
        ):
            # first need to be logged in, let's pretend
            session["_saml_identity"] = resp_session_data[0]
            session["_saml_subject_id"] = "4=id-1"
            session["_saml_state"] = {session_id: resp_session_data[1]}
            success, resp = sp.handle_logout(request, next_url="/next")
            assert session.get("_saml_identity", None) == {}
            assert session.get("_saml_subject_id", None) is None
            assert session.get("_saml_state", None) == {}
            assert success is True
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/next"

    def test_Saml_handle_logout_response_post(
        self, flask_app, sp_config, resp_session_data
    ):
        # create a response to assert upon
        sp = auth.SamlServiceProvider(sp_config)
        session_id, logout_response = create_logout_response(
            "id-1",
            destination="https://sso.example.com/idp/slo",
            issuer_entity_id="https://sso.example.com/idp/metadata",
            req_entity_id="https://foo.example.com/sp/metadata",
        )
        # test SAMLResponse logout as POST
        with flask_app.test_request_context(
            "/",
            method="POST",
            data={
                "SAMLResponse": base64.b64encode(logout_response),
                "RelayState": "/next",
            },
        ):
            endpoints = sp_config["service"]["sp"]["endpoints"]
            slo = endpoints["single_logout_service"][0][0]
            endpoints["single_logout_service"] = [(slo, BINDING_HTTP_POST)]
            # first need to be logged in, let's pretend
            session["_saml_identity"] = resp_session_data[0]
            session["_saml_subject_id"] = "4=id-1"
            session["_saml_state"] = {session_id: resp_session_data[1]}
            success, resp = sp.handle_logout(request, next_url="/next")
            assert success is True
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/next"

    def test_Saml_handle_logout_request(self, flask_app, sp_config, req_session_data):
        # create a response to assert upon
        sp = auth.SamlServiceProvider(sp_config)
        logout_request = create_logout_request(
            subject_id="id-1",
            destination="https://foo.example.com/sp/slo",
            issuer_entity_id="https://sso.example.com/idp/metadata",
            req_entity_id="https://sso.example.com/idp/metadata",
        )
        # test SAMLRequest logout
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={
                "SAMLRequest": deflate_and_base64_encode(str(logout_request)),
                "RelayState": deflate_and_base64_encode(logout_request.id),
            },
        ):
            # first need to be logged in, let's pretend
            session["_saml_identity"] = req_session_data[0]
            session["_saml_subject_id"] = code(
                saml.NameID(
                    name_qualifier="https://sso.example.com/idp/metadata", text="id-1"
                )
            )
            session["_saml_state"] = {"id-" + logout_request.id: req_session_data[1]}
            success, resp = sp.handle_logout(request, next_url="/next")
            assert success is True
            assert resp.status_code == 302
            assert "SAMLResponse" in resp.headers["Location"]
            _url, params = parse_location_header(resp.headers["Location"])
            assert "SAMLResponse" in params
            logout = samlp.logout_response_from_string(
                decode_base64_and_inflate(params["SAMLResponse"][0])
            )
            # CHANGE THIS
            # LOGOUT IS RETURNING Responder STATUS
            assert (
                logout.status.status_code.value
                == "urn:oasis:names:tc:SAML:2.0:status:Responder"
            )
            assert logout.destination == "https://sso.example.com/idp/slo"

    def test_Saml_handle_logout_request_no_subject_id(
        self, flask_app, sp_config, req_session_data
    ):
        # create a response to assert upon
        sp = auth.SamlServiceProvider(sp_config)
        logout_request = create_logout_request(
            subject_id="id-1",
            destination="https://foo.example.com/sp/slo",
            issuer_entity_id="https://sso.example.com/idp/metadata",
            req_entity_id="https://sso.example.com/idp/metadata",
        )
        # test SAMLRequest logout
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={
                "SAMLRequest": deflate_and_base64_encode(str(logout_request)),
                "RelayState": deflate_and_base64_encode(logout_request.id),
            },
        ):
            # first need to be logged in, let's pretend
            session["_saml_identity"] = req_session_data[0]
            session["_saml_subject_id"] = None
            session["_saml_state"] = {"id-" + logout_request.id: req_session_data[1]}
            success, _ = sp.handle_logout(request, next_url="/next")
            assert success is True

    def test_Saml_handle_logout_invalid_missing_all_params(self, flask_app, sp_config):
        # test missing any GET/POST parameters
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert "Unable to find supported binding" == exc_info.value.description

    def test_Saml_handle_logout_invalid_missing_saml_in_get(self, flask_app, sp_config):
        # test missing SAMLRequest/SAMLResponse in GET
        with flask_app.test_request_context(
            "/", method="GET", query_string={"RelayState": "/next"}
        ):
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert (
                "Unable to find SAMLRequest or SAMLResponse"
                == exc_info.value.description
            )

    def test_Saml_handle_logout_invalid_missing_saml_in_post(
        self, flask_app, sp_config
    ):
        # test missing SAMLRequest/SAMLResponse in POST
        with flask_app.test_request_context(
            "/", method="POST", data={"RelayState": "/next"}
        ):
            # tell config to accept POST binding on the slo endpoint
            endpoints = sp_config["service"]["sp"]["endpoints"]
            slo = endpoints["single_logout_service"][0][0]
            endpoints["single_logout_service"] = [(slo, BINDING_HTTP_POST)]
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert (
                "Unable to find SAMLRequest or SAMLResponse"
                == exc_info.value.description
            )

    def test_Saml_handle_logout_invalid_SAMLResponse_get(self, flask_app, sp_config):
        # test invalid SAMLResponse in GET
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={"SAMLResponse": "invalid", "RelayState": "/next"},
        ):
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert "SAML response is invalid" == exc_info.value.description

    def test_Saml_handle_logout_invalid_SAMLResponse_post(self, flask_app, sp_config):
        # test invalid SAMLResponse in POST
        with flask_app.test_request_context(
            "/", method="POST", data={"SAMLResponse": "invalid", "RelayState": "/next"}
        ):
            # tell config to accept POST binding on the slo endpoint
            endpoints = sp_config["service"]["sp"]["endpoints"]
            slo = endpoints["single_logout_service"][0][0]
            endpoints["single_logout_service"] = [(slo, BINDING_HTTP_POST)]
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert "SAML response is invalid" == exc_info.value.description

    def test_Saml_handle_logout_invalid_SAMLRequest(self, flask_app, sp_config):
        # test invalid SAMLRequest
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={"SAMLRequest": "invalid", "RelayState": "/next"},
        ):
            sp = auth.SamlServiceProvider(sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert "SAML request is invalid" == exc_info.value.description
