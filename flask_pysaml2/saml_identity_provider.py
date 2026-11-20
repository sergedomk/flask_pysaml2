import logging

from flask import Request, Response, make_response, session
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.server import Server
from saml2.sigver import encrypt_cert_from_item
from werkzeug.exceptions import BadRequest

from flask_pysaml2.cache import IdentityCache
from flask_pysaml2.saml_provider_base import SamlProviderBase

LOGGER = logging.getLogger(__name__)


class SamlIdentityProvider(SamlProviderBase):
    """
    SAML Wrapper around pysaml2.

    Implements SAML2 Identity Provider functionality for Flask.
    """

    _saml_context = "idp"

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
        # retrieve cache
        identity_cache = IdentityCache(session, "_saml_identity")
        subject_id = session.get("_saml_subject_id")

        LOGGER.debug("Identity cache %s", identity_cache)
        LOGGER.debug("Subject Id %s", subject_id)

        idp_server = Server(self._config, cache=identity_cache)

        if request.args:
            binding = BINDING_HTTP_REDIRECT
        elif request.form:
            binding = BINDING_HTTP_POST
        else:
            raise BadRequest("Unable to find supported binding")

        if "SAMLRequest" in request.values:
            try:
                saml_request = idp_server.parse_authn_request(
                    request.values["SAMLRequest"], binding
                )
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
                _encrypt_cert = encrypt_cert_from_item(saml_request.message)
                resp_args = idp_server.response_args(saml_request)
                _identity = identity_cache.get_identity(subject_id)
                _resp = idp_server.create_authn_response(
                    _identity,
                    userid=subject_id,
                    encrypt_cert=_encrypt_cert,
                    **resp_args,
                )
            except UnknownPrincipal as excp:
                _resp = idp_server.create_error_response(
                    saml_request.id, destination, excp
                )
            except UnsupportedBinding as excp:
                _resp = idp_server.create_error_response(
                    saml_request.id, destination, excp
                )

            http_args = idp_server.apply_binding(
                binding_out,
                f"{_resp}",
                destination,
                relay_state=request.form.get("RelayState", "/"),
                response=True,
            )

            return make_response(
                http_args["data"], http_args["status"], http_args["headers"]
            )

        else:
            raise BadRequest("Unable to find SAMLRequest or SAMLResponse")
