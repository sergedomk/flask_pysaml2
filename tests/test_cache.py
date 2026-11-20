from flask import session
from saml2 import saml

from flask_pysaml2.cache import AuthDictCache, IdentityCache


class TestCache:
    def test_AuthDictCache(self, flask_app):
        with flask_app.test_request_context("/", method="GET"):
            # assert empty session
            assert session == {}
            # create cache pointing at undefined key in empty session
            cache = AuthDictCache(session, "_test")
            # assert empty
            assert cache == {}
            assert cache.session_data == {}
            # verify that cache works like a normal dict
            cache["key_1"] = "value_1"
            assert cache == {"key_1": "value_1"}
            cache["key_2"] = "value_2"
            cache.update({"key_1": "value_4", "key_3": "value_3"})
            assert cache == {"key_1": "value_4", "key_2": "value_2", "key_3": "value_3"}
            # verify that data has not been sync'ed to the session
            assert session == {}
            assert cache.session_data == {}
            # verify that data has been sync'ed to the session
            cache.sync()
            assert cache.session_data == {
                "key_1": "value_4",
                "key_2": "value_2",
                "key_3": "value_3",
            }
            assert session.get("_test") == {
                "key_1": "value_4",
                "key_2": "value_2",
                "key_3": "value_3",
            }
            # if we create a cache pointing to existing session data, it
            # should be populated
            cache = AuthDictCache(session, "_test")
            assert cache == {"key_1": "value_4", "key_2": "value_2", "key_3": "value_3"}

    def test_IdentityCache(self, flask_app):
        with flask_app.test_request_context("/", method="GET"):
            # assert empty session
            assert session == {}
            # create cache pointing at undefined key in empty session
            cache = IdentityCache(session, "_test")
            assert session == {}
            assert cache._db == {}
            assert cache._sync is True
            # Add something to the cache _db
            name_id = saml.NameID("subject_id")
            cache_info = {"name_id": "subject_id"}
            cache.set(name_id, "entity_id", cache_info)
            # verify that data has  been sync'ed to the session automagically
            assert cache._db == {"0=subject_id": {"entity_id": (0, cache_info)}}
            assert session.get("_test") == {
                "0=subject_id": {"entity_id": (0, cache_info)}
            }
            # if we create a cache pointing to existing session data, it
            # should be populated
            cache = IdentityCache(session, "_test")
            assert cache._db == {"0=subject_id": {"entity_id": (0, cache_info)}}
