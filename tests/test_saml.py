import base64
import copy
import os
import time
import urllib.parse as urlparse
from typing import Any

import pytest
from flask import Flask, request, session
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, VERSION, saml, samlp
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.client import Saml2Client
from saml2.config import IdPConfig, SPConfig
from saml2.ident import IdentDB
from saml2.mdstore import locations
from saml2.s_utils import (
    UnsupportedBinding,
    decode_base64_and_inflate,
    deflate_and_base64_encode,
)
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.samlp import Response
from saml2.server import Server
from saml2.sigver import SignatureError
from saml2.time_util import instant
from werkzeug.exceptions import BadRequest

import flask_pysaml2 as auth

from .idp_config import CONFIG as idp_config
from .sp_config import CONFIG as sp_config

root_path = os.path.dirname(os.path.abspath(__file__))

SUPER_SECRET_KEY = "Super secret key. Shhhh!"
AUTHN = {
    "class_ref": INTERNETPROTOCOLPASSWORD,
    "authn_auth": "http://www.example.com/login",
}


def create_authn_response(
    session_id,
    identity: dict | None = None,
    sign_response: bool = True,
    sign_assertion: bool = True,
    encrypt_assertion: bool = False,
) -> tuple[Any, bytes]:
    identity = identity or {}
    config = IdPConfig()
    config.load(idp_config)
    idp_server = Server(config=config)
    idp_server.ident = IdentDB(auth.AuthDictCache({}, "_ident"))
    authn_response = idp_server.create_authn_response(
        identity=identity,
        in_response_to=session_id,
        destination="https://foo.example.com/sp/acs",
        sp_entity_id="https://foo.example.com/sp/metadata",
        name_id_policy=None,
        userid="Irrelevent",
        authn=AUTHN,
        sign_response=sign_response,
        sign_assertion=sign_assertion,
        encrypt_cert=None,  # TODO: Figure out how to make this work.
        encrypt_assertion=encrypt_assertion,
        instance=True,
    )
    if isinstance(authn_response, Response):
        authn_response = str(authn_response)
    response = samlp.response_from_string(authn_response)
    return response.assertion[0].subject.name_id.text, authn_response.encode("utf-8")


def create_logout_response(
    subject_id, destination, issuer_entity_id, req_entity_id, sign: bool = True
) -> tuple[Any, bytes]:
    config = IdPConfig()
    config.load(idp_config)
    idp_server = Server(config=config)
    # construct a request
    logout_request = create_logout_request(
        subject_id=subject_id,
        destination=destination,
        issuer_entity_id=issuer_entity_id,
        req_entity_id=req_entity_id,
    )

    enc_logout_request = deflate_and_base64_encode(f"{logout_request}")
    req_info = idp_server.parse_logout_request(
        enc_logout_request, BINDING_HTTP_REDIRECT
    )
    bindings = [BINDING_HTTP_REDIRECT]
    response = idp_server.create_logout_response(req_info.message, bindings, sign=sign)
    http_args = idp_server.apply_binding(
        BINDING_HTTP_REDIRECT,
        f"{response}",
        destination,
        "relay_state",
        response=True,
    )
    location = dict(http_args.get("headers")).get("Location")
    url = urlparse.urlparse(location)
    params = urlparse.parse_qs(url.query)
    logout_response_xml = decode_base64_and_inflate(params["SAMLResponse"][0])
    response = samlp.logout_response_from_string(logout_response_xml)
    return response.in_response_to, logout_response_xml


def create_logout_request(
    subject_id, destination, issuer_entity_id, req_entity_id, sign: bool = True
) -> samlp.LogoutRequest:
    config = SPConfig()
    config.load(sp_config)
    Saml2Client(config=config)
    # construct a request
    logout_request = samlp.LogoutRequest(
        id="a123456",
        version=VERSION,
        destination=destination,
        issue_instant=instant(),
        issuer=saml.Issuer(text=req_entity_id, format=saml.NAMEID_FORMAT_ENTITY),
        name_id=saml.NameID(
            name_qualifier="https://sso.example.com/idp/metadata",
            format=NAMEID_FORMAT_TRANSIENT,
            text=subject_id,
        ),
    )
    return logout_request


# taken from tests/fakeIDP.py in the pysaml2 repo
def unpack_form(_str, ver="SAMLRequest"):
    SR_STR = f'name="{ver}" value="'
    RS_STR = 'name="RelayState" value="'

    i = _str.find(SR_STR)
    i += len(SR_STR)
    j = _str.find('"', i)

    sr = _str[i:j]

    k = _str.find(RS_STR, j)
    k += len(RS_STR)
    l = _str.find('"', k)

    rs = _str[k:l]

    return {ver: sr, "RelayState": rs}


@pytest.fixture
def flask_app():
    app = Flask(__name__)
    app.secret_key = SUPER_SECRET_KEY
    return app


class TestSaml:
    def test_AuthDictCache(self, flask_app):
        with flask_app.test_request_context("/", method="GET"):
            # assert empty session
            assert session == {}
            # create cache pointing at undefined key in empty session
            cache = auth.AuthDictCache(session, "_test")
            # assert empty
            assert cache == {}
            assert cache.session_data == {}
            # verify that cache works like a normal dict
            cache["key_1"] = "value_1"
            assert cache == {"key_1": "value_1"}
            cache["key_2"] = "value_2"
            cache.update({"key_1": "value_4", "key_3": "value_3"})
            assert cache == {"key_1": "value_4", "key_2": "value_2", "key_3": "value_3"}
            # verify that data has not been sync'ed to the session
            assert session == {}
            assert cache.session_data == {}
            # verify that data has been sync'ed to the session
            cache.sync()
            assert cache.session_data == {
                "key_1": "value_4",
                "key_2": "value_2",
                "key_3": "value_3",
            }
            assert session.get("_test") == {
                "key_1": "value_4",
                "key_2": "value_2",
                "key_3": "value_3",
            }
            # if we create a cache pointing to existing session data, it
            # should be populated
            cache = auth.AuthDictCache(session, "_test")
            assert cache == {"key_1": "value_4", "key_2": "value_2", "key_3": "value_3"}

    def test_IdentityCache(self, flask_app):
        with flask_app.test_request_context("/", method="GET"):
            # assert empty session
            assert session == {}
            # create cache pointing at undefined key in empty session
            cache = auth.IdentityCache(session, "_test")
            assert session == {}
            assert cache._db == {}
            assert cache._sync is True
            # Add something to the cache _db
            name_id = saml.NameID("subject_id")
            cache_info = {"name_id": "subject_id"}
            cache.set(name_id, "entity_id", cache_info)
            # verify that data has  been sync'ed to the session automagically
            assert cache._db == {"0=subject_id": {"entity_id": (0, cache_info)}}
            assert session.get("_test") == {
                "0=subject_id": {"entity_id": (0, cache_info)}
            }
            # if we create a cache pointing to existing session data, it
            # should be populated
            cache = auth.IdentityCache(session, "_test")
            assert cache._db == {"0=subject_id": {"entity_id": (0, cache_info)}}

    def test_Saml_init(self, flask_app):
        entity_id = "https://sso.example.com/idp/metadata"
        with flask_app.test_request_context("/", method="GET"):
            with pytest.raises(TypeError):
                auth.Saml({"service": {"sp": "invalid"}})
            sp = auth.Saml(sp_config)
            # metadata (A single IdP)
            assert sp._config.metadata.identity_providers() == [entity_id]
            # SP end points
            slo = sp._config.metadata.single_logout_service(
                entity_id, binding=BINDING_HTTP_REDIRECT, typ="idpsso"
            )[0]
            assert slo["location"] == "https://sso.example.com/idp/slo"
            assert (
                slo["binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            )
            sso = sp._config.metadata.single_sign_on_service(entity_id)[0]
            assert sso["location"] == "https://sso.example.com/idp/sso"
            assert (
                sso["binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            )
            # Configured default IdP and discovery service
            assert [entity_id] == sp._config.getattr("idp")
            assert "https://ds.example.com/disco" == sp.discovery_service_end_point

    def test_Saml_init_idp_as_inline_dict(self, flask_app):
        tmp_sp_config = copy.deepcopy(sp_config)
        entity_id = "https://sso.example.com/idp/metadata-inline"
        tmp_sp_config["metadata"]["inline_dict"] = [
            {
                "entityid": entity_id,
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
                "cert_file": root_path + "/sso_public.crt",
            }
        ]
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.Saml(tmp_sp_config)
            assert entity_id in sp._config.metadata.identity_providers()
            slo = sp._config.metadata.single_logout_service(
                entity_id, binding=BINDING_HTTP_REDIRECT, typ="idpsso"
            )[0]
            assert slo["location"] == "https://sso.example.com/idp/slo"
            assert (
                slo["binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            )
            sso = sp._config.metadata.single_sign_on_service(entity_id)[0]
            assert sso["location"] == "https://sso.example.com/idp/sso"
            assert (
                sso["binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            )

    def test_Saml_init_idp_as_inline_dict_multicert(self, flask_app):
        tmp_sp_config = copy.deepcopy(sp_config)
        entity_id = "https://sso.example.com/idp/metadata-inline"
        tmp_sp_config["metadata"]["inline_dict"] = [
            {
                "entityid": entity_id,
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
                # Note: You can NOT build metadata from a Config object that doesn't
                # have `cert_file` set. So even if you want to hack in multiple
                # certs, you still have to pass in a valid path to a file.
                "cert_file": root_path + "/sso_public.crt",
                "certs": [
                    {
                        "cert_file": root_path + "/sso_public.crt",
                        "use": "signing",
                    },
                    {
                        "cert_file": root_path + "/sso_alt_public.crt",
                        "use": "both",
                    },
                    {
                        "cert_data": "ThisIsNotReallyACertButItIsAString",
                        "use": "encryption",
                    },
                ],
            }
        ]
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.Saml(tmp_sp_config)
            assert entity_id in sp._config.metadata.identity_providers()
            assert 2 == len(sp._config.metadata.certs(entity_id, "idpsso", "signing"))
            assert 2 == len(
                sp._config.metadata.certs(entity_id, "idpsso", "encryption")
            )


class TestSamlAuthenticate:
    def test_Saml_authenticate(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test signed authentication request
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.Saml(tmp_sp_config)
            resp = sp.authenticate(next_url="/next")
            assert resp.status_code == 302
            assert "SAMLRequest" in resp.headers["Location"]
            url = urlparse.urlparse(resp.headers["Location"])
            assert url.hostname == "sso.example.com"
            assert url.path == "/idp/sso"
            params = urlparse.parse_qs(url.query)
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

    def test_Saml_authenticate_unsigned(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test un-signed authentication request
        with flask_app.test_request_context("/", method="GET"):
            tmp_sp_config["service"]["sp"]["authn_requests_signed"] = None
            sp = auth.Saml(tmp_sp_config)
            resp = sp.authenticate(next_url="/next")
            assert resp.status_code == 302
            url = urlparse.urlparse(resp.headers["Location"])
            params = urlparse.parse_qs(url.query)
            assert "SAMLRequest" in params
            assert "Signature" not in params

    def test_Saml_authenticate_via_post(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test signed authentication request
        with flask_app.test_request_context("/", method="GET"):
            tmp_sp_config["metadata"] = {
                "local": [root_path + "/idp_post_metadata.xml"]
            }
            sp = auth.Saml(tmp_sp_config)
            resp, status = sp.authenticate(next_url="/next", binding=BINDING_HTTP_POST)
            assert status == 200
            _form = unpack_form(resp["data"][3])
            assert "SAMLRequest" in _form
            assert "RelayState" in _form
            authn_id = next(iter(session["_saml_outstanding_queries"].keys()))
            assert session["_saml_outstanding_queries"] == {authn_id: "/next"}

    def test_Saml_authenticate_no_idp_configured(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test using binding method not configured for in IdP metadata
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(
                UnsupportedBinding,
                match="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            ):
                sp.authenticate(next_url="/next", binding=BINDING_HTTP_POST)

    def test_Saml_authenticate_no_idp_allowed(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test with only allowed IdP not included in metadata file
        with flask_app.test_request_context("/", method="GET"):
            tmp_sp_config["metadata"] = {}
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(
                auth.AuthException, match="Unable to locate valid IdP for this request"
            ):
                sp.authenticate(next_url="/next")

    def test_Saml_authenticate_multiple_idps(self, flask_app):
        tmp_sp_config = copy.deepcopy(sp_config)
        entity_id = "https://sso-alt.example.com/idp/metadata"
        tmp_sp_config["metadata"]["inline_dict"] = [
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
                "cert_file": root_path + "/sso_public.crt",
            }
        ]
        # Remove default idp form SP config.
        del tmp_sp_config["service"]["sp"]["idp"]
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.Saml(tmp_sp_config)
            assert None == sp._config.getattr("idp")
            resp = sp.authenticate(next_url="/next")
            assert resp.status_code == 302
            url = urlparse.urlparse(resp.headers["Location"])
            assert url.hostname == "ds.example.com"
            assert url.path == "/disco"
            params = urlparse.parse_qs(url.query)
            assert tmp_sp_config["entityid"] == params["entityID"][0]
            assert (
                "https://foo.example.com/sp/disco_resp?session_id="
                == params["return"][0][:49]
            )

    def test_Saml_authenticate_multiple_idps_with_idp_default(self, flask_app):
        tmp_sp_config = copy.deepcopy(sp_config)
        entity_id = "https://sso-alt.example.com/idp/metadata"
        tmp_sp_config["metadata"]["inline_dict"] = [
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
                "cert_file": root_path + "/sso_public.crt",
            }
        ]
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.Saml(tmp_sp_config)
            resp = sp.authenticate(next_url="/next")
            assert resp.status_code == 302
            assert "SAMLRequest" in resp.headers["Location"]
            url = urlparse.urlparse(resp.headers["Location"])
            assert url.hostname == "sso.example.com"
            assert url.path == "/idp/sso"
            params = urlparse.parse_qs(url.query)
            assert "SAMLRequest" in params
            assert params["RelayState"] == ["/next"]

    def test_Saml_authenticate_required_missing_key_file(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test signed authentication request w/o private key file
        with flask_app.test_request_context("/", method="GET"):
            tmp_sp_config["key_file"] = None
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(
                auth.AuthException,
                match="Signature requested for this Saml authentication request, but no private key file configured",
            ):
                sp.authenticate(next_url="/next")
            # outstanding queury cache should still be empty
            assert session.get("_saml_outstanding_queries", {}) == {}


class TestSamlHandleDiscovery:
    def test_Saml_handle_discovery_response(self, flask_app):
        session_id = "a0123456789abcdef0123456789abcdef"
        tmp_sp_config = copy.deepcopy(sp_config)
        entity_id = "https://sso-alt.example.com/idp/metadata"
        tmp_sp_config["metadata"]["inline_dict"] = [
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
                "cert_file": root_path + "/sso_public.crt",
            }
        ]
        # Remove default idp from SP config.
        del tmp_sp_config["service"]["sp"]["idp"]
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={"session_id": session_id, "entityID": entity_id},
        ):
            # make the client thing there is outstanding request
            session["_saml_outstanding_queries"] = {session_id: "/next"}
            sp = auth.Saml(tmp_sp_config)
            assert None == sp._config.getattr("idp")
            resp = sp.handle_discovery_response(request)
            assert resp.status_code == 302
            assert "SAMLRequest" in resp.headers["Location"]
            url = urlparse.urlparse(resp.headers["Location"])
            assert url.hostname == "sso-alt.example.com"
            assert url.path == "/idp/sso"
            params = urlparse.parse_qs(url.query)
            assert "SAMLRequest" in params
            assert params["RelayState"] == ["/next"]


class TestSamlHandleAssertion:
    def test_Saml_handle_assertion(self, flask_app):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
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
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(Exception):
                sp.handle_assertion(request)

    def test_Saml_handle_assertion_with_default_user_mappings(self, flask_app):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
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
            sp = auth.Saml(tmp_sp_config)
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
    def test_Saml_handle_assertion_encrypted(self, flask_app):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # modifying config in this test, make copy so as not to effect
        # following tests.
        copy.deepcopy(sp_config)
        # create a response to assert upon
        _name_id, _authn_response = create_authn_response(
            session_id, ava, encrypt_assertion=True
        )

    def test_Saml_handle_assertion_allow_unsolicited_without_outstanding_queries(
        self, flask_app
    ):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # The following setting allows for handling unsolicited
        # assertions which ironically is the expected behavior according to
        # the SAML 2.0 specification
        tmp_sp_config["service"]["sp"]["allow_unsolicited"] = "true"
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
            sp = auth.Saml(tmp_sp_config)
            user_attributes, resp = sp.handle_assertion(request)
            assert user_attributes["name_id"][0] == name_id
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/next"
            # identity and subject_id should now be set
            assert name_id in next(iter(session.get("_saml_identity", {}).keys()))
            assert session.get("_saml_subject_id").text == name_id

    def test_Saml_handle_assertion_allow_unsolicited_with_outstanding_queries(
        self, flask_app
    ):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # The following setting allows for handling unsolicited
        # assertions which ironically is the expected behavior according to
        # the SAML 2.0 specification
        tmp_sp_config["service"]["sp"]["allow_unsolicited"] = "true"
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
            sp = auth.Saml(tmp_sp_config)
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

    def test_Saml_handle_assertion_missing_SAMLResponse(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test missing SAMLResponse
        with flask_app.test_request_context("/", method="POST"):
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_assertion(request)
            assert 400 == exc_info.value.code
            assert "SAMLResponse missing from POST" == exc_info.value.description

    def test_Saml_handle_assertion_invalid_SAMLResponse_get(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test SAMLResponse via GET
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={"SAMLResponse": "invalid", "RelayState": "/next"},
        ):
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_assertion(request)
            assert 400 == exc_info.value.code
            assert "SAMLResponse missing from POST" == exc_info.value.description

    def test_Saml_handle_assertion_invalid_SAMLResponse_post(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test invalid SAMLResponse
        with flask_app.test_request_context(
            "/", method="POST", data={"SAMLResponse": "invalid", "RelayState": "/next"}
        ):
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_assertion(request)
            assert 400 == exc_info.value.code
            assert "SAML response is invalid" == exc_info.value.description

    def test_Saml_handle_assertion_invalid_SAMLResponse_signing_required(
        self, flask_app
    ):
        ava = {"uid": "123456"}
        session_id = "a0123456789abcdef0123456789abcdef"
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
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
            sp = auth.Saml(tmp_sp_config)
            # test fails if there is no known outstanding auth request
            with pytest.raises(Exception):
                sp.handle_assertion(request)
            # make the client thing there is outstanding request
            session["_saml_outstanding_queries"] = {session_id: "/next"}
            # test fails if there is not a missing signature
            with pytest.raises(SignatureError, match="Signature missing for response"):
                _user_attributes, _resp = sp.handle_assertion(request)


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

    def test_Saml_logout_signed(self, flask_app, identity_get):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.Saml(tmp_sp_config)
            # first need to be logged in, let's pretend
            session["_saml_identity"] = identity_get
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            resp = sp.logout(next_url="/next")
            assert resp.status_code == 302
            assert "SAMLRequest" in resp.headers["Location"]
            url = urlparse.urlparse(resp.headers["Location"])
            assert url.hostname == "sso.example.com"
            assert url.path == "/idp/slo"
            params = urlparse.parse_qs(url.query)
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

    def test_Saml_logout_unsigned(self, flask_app, identity_get):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test unsigned logout request
        with flask_app.test_request_context("/", method="GET"):
            tmp_sp_config["service"]["sp"]["logout_requests_signed"] = False
            sp = auth.Saml(tmp_sp_config)
            # first need to be logged in, let's pretend
            session["_saml_identity"] = identity_get
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            resp = sp.logout(next_url="/next")
            assert resp.status_code == 302
            assert "SAMLRequest" in resp.headers["Location"]
            url = urlparse.urlparse(resp.headers["Location"])
            params = urlparse.parse_qs(url.query)
            assert "SAMLRequest" in params
            logout = samlp.logout_request_from_string(
                decode_base64_and_inflate(params["SAMLRequest"][0])
            )
            assert logout.signature is None
            # verify state cache shows signing off
            assert session["_saml_state"][logout.id]["sign"] is False

    def test_Saml_logout_via_post(self, flask_app, identity_post):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test signed authentication request
        with flask_app.test_request_context("/", method="GET"):
            tmp_sp_config["metadata"] = {
                "local": [root_path + "/idp_post_metadata.xml"]
            }
            sp = auth.Saml(tmp_sp_config)
            # first need to be logged in, let's pretend
            session["_saml_identity"] = identity_post
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            resp, status = sp.logout(next_url="/next")
            assert status == 200
            _form = unpack_form(resp["data"][3])
            assert "SAMLRequest" in _form
            assert "RelayState" in _form

    def test_Saml_logout_not_logged_in(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(
                auth.AuthException, match="Unable to retrieve subject id for logout"
            ):
                sp.logout(next_url="/next")

    def test_Saml_logout_required_missing_key_file(self, flask_app, identity_get):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        with flask_app.test_request_context("/", method="GET"):
            tmp_sp_config["key_file"] = None
            sp = auth.Saml(tmp_sp_config)
            # first need to be logged in, let's pretend
            session["_saml_identity"] = identity_get
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            with pytest.raises(
                auth.AuthException,
                match="Signature requested for this Saml logout request, but no private key file configured",
            ):
                sp.logout(next_url="/next")


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
    def req_session_data(self):
        not_on_or_after = int(time.time()) + 3600
        identity = {
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
        state = {
            "entity_ids": ["https://sso.example.com/idp/metadata"],
            "name_id": saml.NameID(text="id-1"),
            "entity_id": "https://sso.example.com/idp/metadata",
            "not_on_or_after": not_on_or_after,
            "operation": "SLO",
            "reason": "",
            "sign": False,
        }
        return identity, state

    def test_Saml_handle_logout_response_get(self, flask_app, resp_session_data):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # create a response to assert upon
        sp = auth.Saml(tmp_sp_config)
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
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            session["_saml_state"] = {session_id: resp_session_data[1]}
            success, resp = sp.handle_logout(request, next_url="/next")
            assert session.get("_saml_identity", None) == {}
            assert session.get("_saml_subject_id", None) is None
            assert session.get("_saml_state", None) == {}
            assert success is True
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/next"

    def test_Saml_handle_logout_response_post(self, flask_app, resp_session_data):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # create a response to assert upon
        sp = auth.Saml(tmp_sp_config)
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
            endpoints = tmp_sp_config["service"]["sp"]["endpoints"]
            slo = endpoints["single_logout_service"][0][0]
            endpoints["single_logout_service"] = [(slo, BINDING_HTTP_POST)]
            # first need to be logged in, let's pretend
            session["_saml_identity"] = resp_session_data[0]
            session["_saml_subject_id"] = saml.NameID(text="id-1")
            session["_saml_state"] = {session_id: resp_session_data[1]}
            success, resp = sp.handle_logout(request, next_url="/next")
            assert success is True
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/next"

    def test_Saml_handle_logout_request(self, flask_app, req_session_data):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # create a response to assert upon
        sp = auth.Saml(tmp_sp_config)
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
            session["_saml_subject_id"] = saml.NameID(
                name_qualifier="https://sso.example.com/idp/metadata", text="id-1"
            )
            session["_saml_state"] = {"id-" + logout_request.id: req_session_data[1]}
            success, resp = sp.handle_logout(request, next_url="/next")
            assert success is True
            assert resp.status_code == 302
            assert "SAMLResponse" in resp.headers["Location"]
            url = urlparse.urlparse(resp.headers["Location"])
            params = urlparse.parse_qs(url.query)
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
        self, flask_app, req_session_data
    ):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # create a response to assert upon
        sp = auth.Saml(tmp_sp_config)
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

    def test_Saml_handle_logout_invalid_missing_all_params(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test missing any GET/POST parameters
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert "Unable to find supported binding" == exc_info.value.description

    def test_Saml_handle_logout_invalid_missing_saml_in_get(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test missing SAMLRequest/SAMLResponse in GET
        with flask_app.test_request_context(
            "/", method="GET", query_string={"RelayState": "/next"}
        ):
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert (
                "Unable to find SAMLRequest or SAMLResponse"
                == exc_info.value.description
            )

    def test_Saml_handle_logout_invalid_missing_saml_in_post(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test missing SAMLRequest/SAMLResponse in POST
        with flask_app.test_request_context(
            "/", method="POST", data={"RelayState": "/next"}
        ):
            # tell config to accept POST binding on the slo endpoint
            endpoints = tmp_sp_config["service"]["sp"]["endpoints"]
            slo = endpoints["single_logout_service"][0][0]
            endpoints["single_logout_service"] = [(slo, BINDING_HTTP_POST)]
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert (
                "Unable to find SAMLRequest or SAMLResponse"
                == exc_info.value.description
            )

    def test_Saml_handle_logout_invalid_SAMLResponse_get(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test invalid SAMLResponse in GET
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={"SAMLResponse": "invalid", "RelayState": "/next"},
        ):
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert "SAML response is invalid" == exc_info.value.description

    def test_Saml_handle_logout_invalid_SAMLResponse_post(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test invalid SAMLResponse in POST
        with flask_app.test_request_context(
            "/", method="POST", data={"SAMLResponse": "invalid", "RelayState": "/next"}
        ):
            # tell config to accept POST binding on the slo endpoint
            endpoints = tmp_sp_config["service"]["sp"]["endpoints"]
            slo = endpoints["single_logout_service"][0][0]
            endpoints["single_logout_service"] = [(slo, BINDING_HTTP_POST)]
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert "SAML response is invalid" == exc_info.value.description

    def test_Saml_handle_logout_invalid_SAMLRequest(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test invalid SAMLRequest
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={"SAMLRequest": "invalid", "RelayState": "/next"},
        ):
            sp = auth.Saml(tmp_sp_config)
            with pytest.raises(BadRequest) as exc_info:
                sp.handle_logout(request)
            assert 400 == exc_info.value.code
            assert "SAML request is invalid" == exc_info.value.description


class TestSamlGetMetadata:
    def test_Saml_get_metadata_with_private_key(self, flask_app):
        entity_id = "https://sso.example.com/idp/metadata"
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test with defined private key file
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.Saml(tmp_sp_config)
            resp = sp.get_metadata()
            assert "Content-type: text/xml; charset=utf-8" in str(resp.headers)
            metadata_xml = resp.data
            assert b"Signature" in metadata_xml
            sp._config.load(tmp_sp_config)
            sls = sp._config.metadata.single_logout_service(
                entity_id, binding=BINDING_HTTP_REDIRECT, typ="idpsso"
            )
            assert list(locations(sls)) == ["https://sso.example.com/idp/slo"]
            ssos = sp._config.metadata.single_sign_on_service(entity_id)
            assert list(locations(ssos)) == ["https://sso.example.com/idp/sso"]

    def test_Saml_get_metadata_without_private_key(self, flask_app):
        # modifying config in this test, make copy so as not to effect
        # following tests.
        tmp_sp_config = copy.deepcopy(sp_config)
        # test without defined private key file
        with flask_app.test_request_context("/", method="GET"):
            tmp_sp_config["key_file"] = None
            sp = auth.Saml(tmp_sp_config)
            resp = sp.get_metadata()
            assert "Content-type: text/xml; charset=utf-8" in str(resp.headers)
            metadata_xml = resp.data
            assert b"Signature" not in metadata_xml
