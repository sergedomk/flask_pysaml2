"""
Flask-PySAML2
-------------

This library implements an integration for the Flask web framework to the
PySAML2 library developed by Roland Hedberg.

The Service Provider integration is fairly complete. Identity Provider
integration is still under development.

Copyright (c) 2012, Kavi Corporation
License (Modified BSD License), see LICENSE for more details.
"""

from .exception import AuthException
from .saml_identity_provider import SamlIdentityProvider
from .saml_service_provider import SamlServiceProvider

__all__ = [
    "AuthException",
    "SamlIdentityProvider",
    "SamlServiceProvider",
]
