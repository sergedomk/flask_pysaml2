import pytest
from saml2 import BINDING_HTTP_REDIRECT

import flask_pysaml2 as auth
from tests.helpers import ROOT_PATH


class TestSamlServiceProviderConfig:
    def test_init_invalid(self, flask_app):
        with (
            flask_app.test_request_context("/", method="GET"),
            pytest.raises(TypeError),
        ):
            auth.SamlServiceProvider({"service": {"sp": "invalid"}})

    def test_init(self, flask_app, sp_config):
        entity_id = "https://sso.example.com/idp/metadata"
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.SamlServiceProvider(sp_config)
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

    def test_init_idp_as_inline_dict(self, flask_app, sp_config):
        entity_id = "https://sso.example.com/idp/metadata-inline"
        sp_config["metadata"]["inline_dict"] = [
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
                "cert_file": ROOT_PATH + "/sso_public.crt",
            }
        ]
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.SamlServiceProvider(sp_config)
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

    def test_init_idp_as_inline_dict_multicert(self, flask_app, sp_config):
        entity_id = "https://sso.example.com/idp/metadata-inline"
        sp_config["metadata"]["inline_dict"] = [
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
                "cert_file": ROOT_PATH + "/sso_public.crt",
                "certs": [
                    {
                        "cert_file": ROOT_PATH + "/sso_public.crt",
                        "use": "signing",
                    },
                    {
                        "cert_file": ROOT_PATH + "/sso_alt_public.crt",
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
            sp = auth.SamlServiceProvider(sp_config)
            assert entity_id in sp._config.metadata.identity_providers()
            assert 2 == len(sp._config.metadata.certs(entity_id, "idpsso", "signing"))
            assert 2 == len(
                sp._config.metadata.certs(entity_id, "idpsso", "encryption")
            )


class TestSamlIdentityProviderConfig:
    def test_init_invalid(self, flask_app):
        with (
            flask_app.test_request_context("/", method="GET"),
            pytest.raises(TypeError),
        ):
            auth.SamlIdentityProvider({"service": {"idp": "invalid"}})

    def test_init(self, flask_app, idp_config):
        entity_id = "https://foo.example.com/sp/metadata"
        with flask_app.test_request_context("/", method="GET"):
            idp = auth.SamlIdentityProvider(idp_config)
            # metadata (A single SP)
            assert idp._config.metadata.service_providers() == [entity_id]
            # SP end points
            slo = idp._config.metadata.single_logout_service(
                entity_id, binding=BINDING_HTTP_REDIRECT, typ="spsso"
            )[0]
            assert slo["location"] == "https://foo.example.com/sp/slo"
            assert (
                slo["binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            )
            sso = idp._config.metadata.assertion_consumer_service(entity_id)[0]
            assert sso["location"] == "https://foo.example.com/sp/acs"
            assert sso["binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

    def test_init_idp_as_inline_dict(self, flask_app, idp_config):
        entity_id = "https://foo.example.com/sp/metadata-inline"
        idp_config["metadata"]["inline_dict"] = [
            {
                "entityid": entity_id,
                "contact_person": [
                    {
                        "email_address": "john.smith@foo.example.com",
                        "type": "technical",
                    }
                ],
                "service": {
                    "sp": {
                        "name": "Test Service Provider",
                        "endpoints": {
                            "assertion_consumer_service": [
                                "https://foo.example.com/sp/acs"
                            ],
                            "single_logout_service": [
                                (
                                    "https://foo.example.com/sp/slo",
                                    BINDING_HTTP_REDIRECT,
                                )
                            ],
                        },
                    },
                },
                "cert_file": ROOT_PATH + "/sso_public.crt",
            }
        ]
        with flask_app.test_request_context("/", method="GET"):
            idp = auth.SamlIdentityProvider(idp_config)
            assert entity_id in idp._config.metadata.service_providers()
            # SP end points
            slo = idp._config.metadata.single_logout_service(
                entity_id, binding=BINDING_HTTP_REDIRECT, typ="spsso"
            )[0]
            assert slo["location"] == "https://foo.example.com/sp/slo"
            assert (
                slo["binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            )
            sso = idp._config.metadata.assertion_consumer_service(entity_id)[0]
            assert sso["location"] == "https://foo.example.com/sp/acs"
            assert sso["binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

    def test_init_idp_as_inline_dict_multicert(self, flask_app, idp_config):
        entity_id = "https://foo.example.com/sp/metadata-inline"
        idp_config["metadata"]["inline_dict"] = [
            {
                "entityid": entity_id,
                "contact_person": [
                    {
                        "email_address": "john.smith@foo.example.com",
                        "type": "technical",
                    }
                ],
                "service": {
                    "sp": {
                        "name": "Test Service Provider",
                        "endpoints": {
                            "assertion_consumer_service": [
                                "https://foo.example.com/sp/acs"
                            ],
                            "single_logout_service": [
                                (
                                    "https://foo.example.com/sp/slo",
                                    BINDING_HTTP_REDIRECT,
                                )
                            ],
                        },
                    },
                },
                # Note: You can NOT build metadata from a Config object that doesn't
                # have `cert_file` set. So even if you want to hack in multiple
                # certs, you still have to pass in a valid path to a file.
                "cert_file": ROOT_PATH + "/sso_public.crt",
                "certs": [
                    {
                        "cert_file": ROOT_PATH + "/sso_public.crt",
                        "use": "signing",
                    },
                    {
                        "cert_file": ROOT_PATH + "/sso_alt_public.crt",
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
            idp = auth.SamlIdentityProvider(idp_config)
            assert entity_id in idp._config.metadata.service_providers()
            assert 2 == len(idp._config.metadata.certs(entity_id, "spsso", "signing"))
            assert 2 == len(
                idp._config.metadata.certs(entity_id, "spsso", "encryption")
            )
