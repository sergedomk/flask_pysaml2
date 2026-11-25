import logging

from flask import Request, Response, make_response
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.saml import NameID
from saml2.server import Server
from saml2.sigver import encrypt_cert_from_item
from saml2.time_util import in_a_while
from werkzeug.exceptions import BadRequest

from flask_pysaml2.saml_provider_base import SamlProviderBase

LOGGER = logging.getLogger(__name__)


class SamlIdentityProvider(SamlProviderBase):
    """
    SAML Wrapper around pysaml2.

    Implements SAML2 Identity Provider functionality for Flask.
    """

    _saml_context = "idp"

    def add_user_identity(self, subject_id: NameID, session_info: dict):
        """Add the specified user identity to the identity cache"""
        return self.users.add_information_about_person(
            {
                "issuer": self._config.entityid,
                "name_id": subject_id,
                "not_on_or_after": in_a_while(minutes=5),
            }
            | session_info
        )

    def handle_sso_request(self, request: Request) -> Response:
        """Handle SAML Authentication SSO request.

        Args:
            request (Request): Flask request object for this HTTP transaction.

        Returns:
            Flask response object with SAML SSO Authn Response. Response is either
            a redirect or a form which will automatically trigger a POST to the
            assertion endpoint of the Service Provider (SP)

        Raises:
            BadRequest: when error with SAML response from Identity Provider.
        """
        subject_id = self.subject_id_from_session

        LOGGER.debug("Identity cache %s", self.identity_cache)
        LOGGER.debug("Subject Id %s", subject_id)

        idp_server = Server(config=self._config, cache={})

        if request.args:
            binding = BINDING_HTTP_REDIRECT
        elif request.form:
            binding = BINDING_HTTP_POST
        else:
            raise BadRequest("Unable to find supported binding")

        if "SAMLRequest" in request.values:
            try:
                saml_request = idp_server.parse_authn_request(
                    enc_request=request.values["SAMLRequest"],
                    binding=binding,
                    sigalg=request.values.get("SigAlg"),
                    signature=request.values.get("Signature"),
                ).message
            except KeyError:
                raise BadRequest("Message signature verification failure")

            try:
                binding_out, destination = idp_server.pick_binding(
                    "assertion_consumer_service",
                    entity_id=saml_request.issuer.text,
                    request=saml_request,
                )
            except Exception as err:
                LOGGER.error("Couldn't find receiver endpoint: %s", err)
                raise

            try:
                resp_args = idp_server.response_args(saml_request)
                _identity = self.get_user_identity(subject_id)
                _resp = idp_server.create_authn_response(
                    identity=_identity,
                    userid=subject_id,
                    name_id=subject_id,
                    encrypt_cert=encrypt_cert_from_item(saml_request),
                    authn={
                        "class_ref": INTERNETPROTOCOLPASSWORD,
                        "authn_auth": "http://www.example.com/login",
                    },
                    **resp_args,
                )
            except UnknownPrincipal as exc:
                _resp = idp_server.create_error_response(
                    saml_request.id, destination, exc
                )
            except UnsupportedBinding as exc:
                _resp = idp_server.create_error_response(
                    saml_request.id, destination, exc
                )

            http_args = idp_server.apply_binding(
                binding_out,
                f"{_resp}",
                destination,
                relay_state=request.values.get("RelayState", "/"),
                response=True,
            )

            return make_response(
                http_args["data"], http_args["status"], http_args["headers"]
            )

        else:
            raise BadRequest("Unable to find SAMLRequest or SAMLResponse")
