import base64
import os
import urllib.parse as urlparse
from typing import Any

from saml2 import BINDING_HTTP_REDIRECT, VERSION, saml, samlp
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.client import Saml2Client
from saml2.config import config_factory
from saml2.ident import IdentDB
from saml2.s_utils import decode_base64_and_inflate, deflate_and_base64_encode
from saml2.server import Server
from saml2.time_util import instant

from flask_pysaml2.cache import AuthDictCache

from .idp_config import CONFIG as IDP_CONFIG
from .sp_config import CONFIG as SP_CONFIG

AUTHN = {
    "class_ref": INTERNETPROTOCOLPASSWORD,
    "authn_auth": "http://www.example.com/login",
}

ROOT_PATH = os.path.dirname(os.path.abspath(__file__))


def parse_location_header(location: str) -> tuple[urlparse.ParseResult, dict]:
    url = urlparse.urlparse(location)
    params = urlparse.parse_qs(url.query)
    return url, params


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


def create_authn_request(binding: str, sign_post: bool = False) -> str:
    config = config_factory("sp", SP_CONFIG)
    client = Saml2Client(config)
    _, request = client.create_authn_request(
        vorg="https://foo.example.com/sp/metadata",
        destination="https://sso.example.com/idp/sso",
        binding=binding,
        sign=sign_post,
    )
    return str(request)


def get_signature_for_authn_request(message, sigalg) -> bytes:
    config = config_factory("sp", SP_CONFIG)
    client = Saml2Client(config)
    signer = client.sec.sec_backend.get_signer(sigalg)
    string = f"{urlparse.urlencode({'SAMLRequest': message})}&{urlparse.urlencode({'SigAlg': sigalg})}"
    string_enc = string.encode("ascii")
    return base64.b64encode(signer.sign(string_enc))


def create_authn_response(
    session_id,
    identity: dict | None = None,
    sign_response: bool = True,
    sign_assertion: bool = True,
    encrypt_assertion: bool = False,
) -> tuple[Any, bytes]:
    identity = identity or {}
    config = config_factory("idp", IDP_CONFIG)
    idp_server = Server(config=config)
    idp_server.ident = IdentDB(AuthDictCache({}, "_ident"))
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
    if isinstance(authn_response, samlp.Response):
        authn_response = str(authn_response)
    response = samlp.response_from_string(authn_response)
    return response.assertion[0].subject.name_id.text, authn_response.encode("utf-8")


def create_logout_request(
    subject_id, destination, issuer_entity_id, req_entity_id, sign: bool = True
) -> samlp.LogoutRequest:
    config = config_factory("sp", SP_CONFIG)
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
            format=saml.NAMEID_FORMAT_TRANSIENT,
            text=subject_id,
        ),
    )
    return logout_request


def create_logout_response(
    subject_id, destination, issuer_entity_id, req_entity_id, sign: bool = True
) -> tuple[Any, bytes]:
    config = config_factory("idp", IDP_CONFIG)
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
