import logging
import os
from time import struct_time
from typing import Any, Literal

from flask import Request, Response, make_response, redirect, session
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.s_utils import UnravelError, sid
from saml2.saml import NameID
from werkzeug.exceptions import BadRequest

from flask_pysaml2.exception import AuthException
from flask_pysaml2.saml_provider_base import SamlProviderBase

LOGGER = logging.getLogger(__name__)


def _handle_logout_request(
    client: Saml2Client, request: Request, subject_id: NameID | None, binding: str
) -> Response:
    """Handle SAML Authentication logout request (GET).

    Args:
        client (Saml2Client): instance of SAML client class.
        request (Request): Flask request object for this HTTP transaction.
        subject_id (NameID): Id of the subject we are processing the
            logout for.
        binding (string): the SAML binding method being used for this
            request.

    Returns:
        Flask Response object to return to user containing
            HTTP_REDIRECT SAML message.

    Raises:
        BadRequest: when SAML request data is missing.
        AuthException: when SAML request indicates logout failed.
    """
    LOGGER.debug("Received a logout request from Identity Provider")

    # pysaml2 logout_request currently only returns for
    # BINDING_HTTP_REDIRECT. We will have it fail for anything
    # other than the header 'Location'

    try:
        response = client.handle_logout_request(
            request.values["SAMLRequest"],
            subject_id,
            binding=binding,
            relay_state=request.values["RelayState"],
        )
    except (UnravelError, TypeError):
        raise BadRequest("SAML request is invalid")

    try:
        assert response["headers"] is not None
        assert isinstance(response["headers"], list)
        for header in response["headers"]:
            if isinstance(header, tuple):
                tag, data = header
                if tag == "Location":
                    return redirect(data)
    except:
        raise AuthException("An error occurred during logout")


def _handle_logout_response(
    client: Saml2Client, request: Request, binding: str, next_url: str
) -> Response:
    """Handle SAML Authentication logout response (GET or POST).

    Args:
        client (Saml2Client): instance of SAML client class.
        request (Request): Flask request object for this HTTP transaction.
        binding (string): the SAML binding method being used for this
            request.
        next_url (string): URL to get redirected to if all is successful.

    Returns:
        Flask Response object to return to user containing
            HTTP_REDIRECT SAML message.

    Raises:
        BadRequest: when SAML response data is missing.
        AuthException: when SAML response indicates logout failed.
    """
    LOGGER.debug("Received a logout response from Identity Provider")
    try:
        response = client.parse_logout_request_response(
            request.values["SAMLResponse"], binding
        )
        saml_response = client.handle_logout_response(response)
    except (UnravelError, TypeError):
        raise BadRequest("SAML response is invalid")
    LOGGER.debug(saml_response)
    if saml_response:
        if saml_response[1] == "":  # used SOAP BINDING successfully
            response = redirect(next_url)
        else:
            # body, status, headers
            response = make_response(
                "\n".join(saml_response[3]), saml_response[1], saml_response[2]
            )
            # pysaml2 returns an empty 200 in some cases,
            # we'll redirect instead
            if response.status_code == 200 and not response.data:
                response = redirect(next_url)
    else:
        raise AuthException("An error occurred during logout")
    return response


class SamlServiceProvider(SamlProviderBase):
    """
    SAML Wrapper around pysaml2.

    Implements SAML2 Service Provider functionality for Flask.
    """

    _saml_context = "sp"

    def __init__(self, config):
        """Initialize SAML Service Provider.

        Args:
            config (dict): Service Provider config info in dict form
        """
        super().__init__(config)
        # Set discovery end point, if configured for.
        if config["service"]["sp"].get("ds"):
            self.discovery_service_end_point = config["service"]["sp"].get("ds")[0]

    def authenticate(
        self,
        next_url: str = "/",
        binding: str = BINDING_HTTP_REDIRECT,
        selected_idp: str | None = None,
    ) -> Response | tuple[dict, Literal[200]]:
        """Start SAML Authentication login process.

        Args:
            next_url (string): HTTP URL to return user to when authentication
                is complete.
            binding (binding): Saml2 binding method to use for request.
                Defaults to BINDING_HTTP_REDIRECT (don't change til HTTP_POST
                support is complete in pysaml2).
            selected_idp (string): A specfic IdP that should be used to
                authenticate. Defaults to `None`.

        Returns:
            Flask Response object to return to user containing either
                HTTP_REDIRECT or HTTP_POST SAML message.

        Raises:
            AuthException: when unable to locate valid IdP.
            BadRequest: when invalid result returned from SAML client.
        """
        # Fail if signing requested but no private key configured.
        if self._config.getattr("authn_requests_signed") is True and (
            not self._config.key_file or not os.path.exists(self._config.key_file)
        ):
            raise AuthException(
                "Signature requested for this Saml authentication"
                + " request, but no private key file configured"
            )

        # Find configured for IdPs for requested binding method.
        bindable_idps = []
        all_idps = self._config.metadata.identity_providers()
        # Filter IdPs to allowed IdPs, if we have some.
        if self._config.getattr("idp") is not None:
            all_idps = list(set(all_idps) & set(self._config.getattr("idp")))
        # Filter IdPs to selected IdP, if we have one.
        if selected_idp is not None:
            all_idps = list(set(all_idps) & {selected_idp})
        # From all IdPs allowed/selected, get the ones we can bind to.
        for idp in all_idps:
            if self._config.metadata.single_sign_on_service(idp, binding) != []:
                bindable_idps.append(idp)
        if not len(bindable_idps):
            raise AuthException("Unable to locate valid IdP for this request")

        LOGGER.debug("Outstanding queries cache %s", self.outstanding_queries_cache)

        if len(bindable_idps) > 1:
            # Redirect to discovery service
            (session_id, response) = self._handle_discovery_request()
        else:
            idp_entityid = bindable_idps[0]
            LOGGER.debug("Connecting to Identity Provider %s", idp_entityid)

            # Make pysaml2 call to authenticate.
            client = Saml2Client(self._config)
            (session_id, result) = client.prepare_for_authenticate(
                entityid=idp_entityid,
                relay_state=next_url,
                sign=self._config.getattr("authn_requests_signed"),
                binding=binding,
            )

            # The psaml2 source for this method indicates that
            # BINDING_HTTP_POST should not be used right now to authenticate.
            # Regardless, we'll check for it and act accordingly.

            if binding == BINDING_HTTP_REDIRECT:
                LOGGER.debug(
                    "Redirect to Identity Provider %s ( %s )", idp_entityid, result
                )
                response = make_response("", 302, dict(result["headers"]))
            elif binding == BINDING_HTTP_POST:
                LOGGER.debug(
                    "Post to Identity Provider %s ( %s )", idp_entityid, result
                )
                response = result, 200
            else:
                raise BadRequest("Invalid result returned from SAML client")

        LOGGER.debug("Saving session_id ( %s ) in outstanding queries", session_id)
        # cache the outstanding query
        self.outstanding_queries_cache.update({session_id: next_url})
        self.outstanding_queries_cache.sync()

        LOGGER.debug(
            "Outstanding queries cache %s", session["_saml_outstanding_queries"]
        )

        return response

    def _handle_discovery_request(self) -> tuple[str, Response]:
        """Handle SAML Discovery Service request. This method is called
        internally by the `authenticate` method when multiple acceptable IdPs
        are detected.

        Returns:
            Tuple containing session Id and Flask Response object to return to
                user containing either HTTP_REDIRECT to configured Discovery
                Service end point.

        Raises:
            AuthException: when unable to find discovery response end point.
        """
        session_id = sid()
        try:
            return_url = self._config.getattr("endpoints", "sp")["discovery_response"][
                0
            ][0]
        except KeyError:
            raise AuthException(
                "Multiple IdPs configured with no configured Discovery"
                + " response end point."
            )
        return_url += f"?session_id={session_id}"
        disco_url = Saml2Client.create_discovery_service_request(
            self.discovery_service_end_point,
            self._config.entityid,
            **{"return": return_url},
        )
        LOGGER.debug("Redirect to Discovery Service %s", disco_url)
        return session_id, make_response("", 302, {"Location": disco_url})

    def handle_discovery_response(
        self, request: Request
    ) -> Response | tuple[dict, Literal[200]]:
        """Handle SAML Discovery Service response. This method is basically
        a wrapper around `authenticate` with a little extra logic for getting
        the `entityID` out of the request and the next_url and binding that was
        previously submitted to `authenticate` from the user's session.

        Args:
            request (Request): Flask request object for this HTTP transaction.

        Returns:
            Flask Response object to return to user containing either
                HTTP_REDIRECT or HTTP_POST SAML message.

        Raises:
            AuthException: when unable to locate valid IdP.
            BadRequest: when invalid result returned from SAML client.
        """
        session_id = request.args.get("session_id")
        next_url = "/"

        # Retrieve cache. Get `next_url` from cache.
        if session_id in self.outstanding_queries_cache:
            next_url = self.outstanding_queries_cache[session_id]
            del self.outstanding_queries_cache[session_id]
        self.outstanding_queries_cache.sync()
        # Get the selected IdP from the Discovery Service response.
        selected_idp = Saml2Client.parse_discovery_service_response(
            query=request.query_string, returnIDParam=b"entityID"
        )
        selected_idp = selected_idp.decode("utf-8") if selected_idp else ""
        return self.authenticate(next_url=next_url, selected_idp=selected_idp)

    def handle_assertion(self, request: Request) -> tuple[dict, Response]:
        """Handle SAML Authentication login assertion (POST).

        Args:
            request (Request): Flask request object for this HTTP transaction.

        Returns:
            (tuple) SAML assertion response information (dict) containing the
                IdP entity id, the subject's name id, and any additional
                attributes which may have been returned in the assertion, and
                Redirect Flask response object to return user to now that
                authentication is complete.

        Raises:
            BadRequest: when error with SAML response from Identity Provider.
            AuthException: when unable to locate uid attribute in response.
        """
        if not request.form.get("SAMLResponse"):
            raise BadRequest("SAMLResponse missing from POST")

        LOGGER.debug("Outstanding queries cache %s", self.outstanding_queries_cache)
        LOGGER.debug("Identity cache %s", self.identity_cache)

        # use pysaml2 to process the SAML authentication response
        client = Saml2Client(self._config, identity_cache=self.identity_cache)
        saml_response = client.parse_authn_request_response(
            request.form["SAMLResponse"],
            BINDING_HTTP_POST,
            outstanding=self.outstanding_queries_cache,
        )
        if saml_response is None:
            raise BadRequest("SAML response is invalid")
        # make sure outstanding query cache is cleared for this session_id
        session_id = saml_response.session_id()
        if session_id in self.outstanding_queries_cache:
            del self.outstanding_queries_cache[session_id]
        self.outstanding_queries_cache.sync()

        saml_subject_id = saml_response.name_id
        # Assemble SAML assertion info for returning to the method caller.
        saml_assertion_info = saml_response.get_identity()
        # Note: SAML assertion attributes can have multiple values so the
        # values returned for these attributes are lists even if there is only
        # one entry. For consistency the `name_id` returned with the SAML
        # assertion information has been included as a single item list.
        saml_assertion_info["name_id"] = [saml_response.get_subject().text]
        # The IdP entity id is obviously not an attribute, so no list required.
        saml_assertion_info["idp_entity_id"] = saml_response.issuer()
        LOGGER.debug("SAML Session Info ( %s )", saml_assertion_info)

        # set subject Id in cache to retrieved name_id
        self.set_subject_id_in_session(saml_subject_id)

        LOGGER.debug(
            "Outstanding queries cache %s", session["_saml_outstanding_queries"]
        )
        LOGGER.debug("Identity cache %s", session["_saml_identity"])
        LOGGER.debug("Subject Id %s", session["_saml_subject_id"])

        relay_state = request.form.get("RelayState", "/")
        LOGGER.debug("Returning redirect to %s", relay_state)
        return saml_assertion_info, redirect(relay_state)

    def logout(
        self, next_url: str = "/", expire: struct_time | str | int | None = None
    ) -> Response | tuple[Any, int]:
        """Start SAML Authentication logout process.

        Args:
            next_url (string): HTTP URL to return user to when logout is
                complete.
            expire (struct_time): The latest the log out should happen.

        Returns:
            Flask Response object to return to user containing either
                HTTP_REDIRECT or HTTP_POST SAML message.

        Raises:
            AuthException: Can not resolve IdP single logout end-point.
        """
        subject_id = self.subject_id_from_session

        # don't logout if not logged in
        if subject_id is None:
            raise AuthException("Unable to retrieve subject id for logout")
        # fail if signing requested but no private key configured
        if self._config.getattr("logout_requests_signed") is True:
            LOGGER.debug("key_file %s", self._config.key_file)
            if not self._config.key_file or not os.path.exists(self._config.key_file):
                raise AuthException(
                    "Signature requested for this Saml logout request,"
                    + " but no private key file configured"
                )

        LOGGER.debug("State cache %s", self.state_cache)
        LOGGER.debug("Identity cache %s", self.identity_cache)
        LOGGER.debug("Subject Id %s", subject_id)

        # use pysaml2 to initiate the SAML logout request
        client = Saml2Client(
            self._config,
            state_cache=self.state_cache,
            identity_cache=self.identity_cache,
        )
        saml_response = client.global_logout(subject_id, expire=expire)

        # sync the state to cache
        self.state_cache.sync()

        LOGGER.debug("State cache %s", session["_saml_state"])
        LOGGER.debug("Identity cache %s", session["_saml_identity"])

        if saml_response.get("1", None) == "":  # used SOAP BINDING successfully
            return redirect(next_url)

        LOGGER.debug(
            "Returning Response from SAML for continuation of the" + " logout process"
        )
        for item in saml_response.values():
            if isinstance(item, tuple):
                http_type, htargs = item
                break

        if http_type == BINDING_HTTP_POST:
            return htargs, 200
        else:
            return make_response("", 302, htargs["headers"])

    def handle_logout(
        self, request: Request, next_url: str = "/"
    ) -> tuple[bool, Response]:
        """Handle SAML Authentication logout request/response.

        Args:
            request (Request): Flask request object for this HTTP transaction.
            next_url (string): URL to get redirected to if all is successful.

        Returns:
            (boolean) Success, Flask Response object to return to user
                containing HTTP_REDIRECT SAML message.

        Raises:
            BadRequest: when SAML request/response data is missing.
        """
        subject_id = self.subject_id_from_session

        LOGGER.debug("State cache %s", self.state_cache)
        LOGGER.debug("Identity cache %s", self.identity_cache)
        LOGGER.debug("Subject Id %s", subject_id)

        # use pysaml2 to complete the SAML logout request
        client = Saml2Client(
            self._config,
            state_cache=self.state_cache,
            identity_cache=self.identity_cache,
        )
        # let's try to figure out what binding is being used and what type of
        # logout call we are handling
        if request.args:
            binding = BINDING_HTTP_REDIRECT
        elif request.form:
            binding = BINDING_HTTP_POST
        else:
            # The SOAP binding is only valid on logout requests which currently
            # pysaml2 doesn't support.
            raise BadRequest("Unable to find supported binding")

        if "SAMLRequest" in request.values:
            response = _handle_logout_request(client, request, subject_id, binding)
        elif "SAMLResponse" in request.values:
            response = _handle_logout_response(client, request, binding, next_url)
        else:
            raise BadRequest("Unable to find SAMLRequest or SAMLResponse")

        # cache the state and remove subject if logout was successful or
        # this subject was already logged out.
        success = not subject_id or self.identity_cache.get_identity(subject_id) == (
            {},
            [],
        )
        if success:
            session.pop("_saml_subject_id", None)
        self.state_cache.sync()

        LOGGER.debug("State cache %s", session["_saml_state"])
        LOGGER.debug("Identity cache %s", session["_saml_identity"])

        LOGGER.debug("Returning redirect to complete/continue the logout process")
        return success, response
