from flask import request, session
from saml2 import BINDING_HTTP_REDIRECT

import flask_pysaml2 as auth
from tests.helpers import ROOT_PATH, parse_location_header


class TestSamlHandleDiscovery:
    def test_Saml_handle_discovery_response(self, flask_app, sp_config):
        session_id = "a0123456789abcdef0123456789abcdef"
        entity_id = "https://sso-alt.example.com/idp/metadata"
        sp_config["metadata"]["inline_dict"] = [
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
                "cert_file": ROOT_PATH + "/sso_public.crt",
            }
        ]
        # Remove default idp from SP config.
        del sp_config["service"]["sp"]["idp"]
        with flask_app.test_request_context(
            "/",
            method="GET",
            query_string={"session_id": session_id, "entityID": entity_id},
        ):
            # make the client thing there is outstanding request
            session["_saml_outstanding_queries"] = {session_id: "/next"}
            sp = auth.SamlServiceProvider(sp_config)
            assert None == sp._config.getattr("idp")
            resp = sp.handle_discovery_response(request)
            assert resp.status_code == 302
            assert "SAMLRequest" in resp.headers["Location"]
            url, params = parse_location_header(resp.headers["Location"])
            assert url.hostname == "sso-alt.example.com"
            assert url.path == "/idp/sso"
            assert "SAMLRequest" in params
            assert params["RelayState"] == ["/next"]
