from flask import Response, make_response
from saml2.config import config_factory
from saml2.metadata import entity_descriptor, sign_entity_descriptor
from saml2.sigver import security_context

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

    def get_metadata(self) -> Response:
        """Returns SAML Service Provider Metadata"""
        edesc = entity_descriptor(self._config)
        if self._config.key_file:
            _, edesc = sign_entity_descriptor(
                edesc, None, security_context(self._config)
            )
        response = make_response(str(edesc))
        response.headers["Content-type"] = "text/xml; charset=utf-8"
        return response
