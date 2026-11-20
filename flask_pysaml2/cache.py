from saml2.cache import Cache


class AuthDictCache(dict):
    """
    Adapter to make working with session cache easier
    """

    def __init__(self, session_instance, key):
        self.session = session_instance
        self.key = key
        super().__init__(self.session_data)

    @property
    def session_data(self):
        """Return session data associated with this cache"""
        return self.session.get(self.key, {})

    def sync(self):
        """Sync's the cache object with the underlying session store"""
        objs = {}
        objs.update(self)
        self.session[self.key] = objs


class IdentityCache(Cache):
    """
    Adapter for the Identity Cache pysaml2 Cache object
    """

    def __init__(self, session_instance, key):
        super().__init__()
        self._db = AuthDictCache(session_instance, key)
        self._sync = True
