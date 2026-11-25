from functools import cached_property

from flask import Response, make_response, session
from saml2.config import config_factory
from saml2.ident import code, decode
from saml2.metadata import entity_descriptor, sign_entity_descriptor
from saml2.population import Population
from saml2.saml import NameID
from saml2.sigver import security_context

from flask_pysaml2.cache import AuthDictCache, IdentityCache
from flask_pysaml2.utils import parse_metadata_dict_to_inline


class SamlProviderBase:
    _saml_context = None

    def __init__(self, config):
        """Initialize SAML Provider.

        Args:
            config (dict): Provider config info in dict form
        """
        if config.get("metadata") is not None:
            config["metadata"] = parse_metadata_dict_to_inline(
                config["metadata"], typ=self._saml_context
            )
        self._config = config_factory(self._saml_context, config)
        self._config.setattr("", "allow_unknown_attributes", True)

    @property
    def subject_id_from_session(self) -> NameID | None:
        """The stored subject id from session."""
        if not session.get("_saml_subject_id"):
            return None
        return decode(session.get("_saml_subject_id"))

    @cached_property
    def state_cache(self) -> AuthDictCache:
        """State cache stored in session."""
        return AuthDictCache(session, "_saml_state")

    @cached_property
    def outstanding_queries_cache(self) -> AuthDictCache:
        """Outstanding queries cache stored in session."""
        return AuthDictCache(session, "_saml_outstanding_queries")

    @cached_property
    def identity_cache(self) -> IdentityCache:
        """Identity cache stored in session."""
        return IdentityCache(session, "_saml_identity")

    @cached_property
    def users(self) -> Population:
        """Users from Population wrapper on identity cache."""
        return Population(self.identity_cache)

    @staticmethod
    def set_subject_id_in_session(subject_id: NameID | str | None):
        """Set subject id in session.

        Args:
            subject_id (NameID): The subject Id to set
        """
        if isinstance(subject_id, NameID):
            subject_id = code(subject_id)
        session["_saml_subject_id"] = subject_id

    def get_user_identity(self, subject_id: NameID | None) -> dict:
        """The specified user identity from the identity cache.

        Args:
            subject_id (NameId): NameId for identity we are looking for
        """
        _identity, _ = self.users.get_identity(subject_id)
        return _identity

    def get_metadata(self) -> Response:
        """Returns SAML Provider Metadata."""
        edesc = entity_descriptor(self._config)
        if self._config.key_file:
            _, edesc = sign_entity_descriptor(
                edesc, None, security_context(self._config)
            )
        response = make_response(str(edesc))
        response.headers["Content-type"] = "text/xml; charset=utf-8"
        return response
