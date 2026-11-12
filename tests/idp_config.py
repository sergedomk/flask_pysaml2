import os

from saml2 import BINDING_HTTP_REDIRECT

root_path = os.path.dirname(os.path.abspath(__file__))

CONFIG = {
    "entityid": "https://sso.example.com/idp/metadata",
    "contact_person": [
        {
            "given_name": "John",
            "sur_name": "Smith",
            "email_address": "john.smith@sso.example.com",
            "type": "technical",
        }
    ],
    "service": {
        "idp": {
            "name": "Test Service Provider",
            "endpoints": {
                "single_sign_on_service": [
                    ("https://sso.example.com/idp/sso", BINDING_HTTP_REDIRECT)
                ],
                "single_logout_service": [
                    ("https://sso.example.com/idp/slo", BINDING_HTTP_REDIRECT)
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
    "debug": True,
    "xmlsec_binary": "/usr/bin/xmlsec1",
    "key_file": root_path + "/sso_private.key",
    "cert_file": root_path + "/sso_public.crt",
    "ca_certs": None,
    "metadata": {
        "local": [root_path + "/sp_metadata.xml"],
    },
}


if __name__ == "__main__":
    # This logic here allows you to regenerate the metadata XML should it be needed.
    # For example, the certificates expire in 10 years. The reason I added this code
    # was because the prior certificates also expired after 10 years, and they were
    # expired when I came in to update this code.
    #
    # To rebuild the metadata xml file, run the following from within this folder:
    #
    #     $ python idp_config.py > idp_metadata.xml

    from saml2.config import IdPConfig
    from saml2.metadata import entity_descriptor, sign_entity_descriptor
    from saml2.sigver import security_context

    config = IdPConfig()
    config.load(CONFIG)
    edesc = entity_descriptor(config)
    if config.key_file:
        _, edesc = sign_entity_descriptor(edesc, None, security_context(config))

    print(edesc)
