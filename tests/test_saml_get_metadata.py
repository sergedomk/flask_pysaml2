import flask_pysaml2 as auth


class TestSamlSPGetMetadata:
    def test_Saml_get_metadata_with_private_key(self, flask_app, sp_config):
        # test with defined private key file
        with flask_app.test_request_context("/", method="GET"):
            sp = auth.SamlServiceProvider(sp_config)
            resp = sp.get_metadata()
            assert "Content-type: text/xml; charset=utf-8" in str(resp.headers)
            metadata_xml = resp.data
            assert b"Signature" in metadata_xml

    def test_Saml_get_metadata_without_private_key(self, flask_app, sp_config):
        # test without defined private key file
        with flask_app.test_request_context("/", method="GET"):
            sp_config["key_file"] = None
            sp = auth.SamlServiceProvider(sp_config)
            resp = sp.get_metadata()
            assert "Content-type: text/xml; charset=utf-8" in str(resp.headers)
            metadata_xml = resp.data
            assert b"Signature" not in metadata_xml


class TestSamlIdPGetMetadata:
    def test_Saml_get_metadata_with_private_key(self, flask_app, idp_config):
        # test with defined private key file
        with flask_app.test_request_context("/", method="GET"):
            idp = auth.SamlIdentityProvider(idp_config)
            resp = idp.get_metadata()
            assert "Content-type: text/xml; charset=utf-8" in str(resp.headers)
            metadata_xml = resp.data
            assert b"Signature" in metadata_xml

    def test_Saml_get_metadata_without_private_key(self, flask_app, idp_config):
        # test without defined private key file
        with flask_app.test_request_context("/", method="GET"):
            idp_config["key_file"] = None
            idp = auth.SamlIdentityProvider(idp_config)
            resp = idp.get_metadata()
            assert "Content-type: text/xml; charset=utf-8" in str(resp.headers)
            metadata_xml = resp.data
            assert b"Signature" not in metadata_xml
