Using ``flask_pysaml2`` in your Flask app
-----------------------------------------

Flask-pysaml2 uses the same config as pysaml2
(`<https://pysaml2.readthedocs.io/en/latest/howto/config.html>`__)
with two notable additions. To facilitate dynamically configured IPDs,
we've added an `inline_dict` for metadata. We, also, added the ability
to have multiple certificates for an inline IDP.

Below are rather simplified examples of using in a Flask app. The
`examples` folder includes more complete examples.

Service Provider
================

.. code-block:: python

    from flask import Flask, request
    from flask_login import LoginManager, UserMixin, login_required, login_user
    import flask_pysaml2

    app = Flask(__name__)
    app.secret_key = "SUPER_SECRET_KEY"
    sp = flask_pysaml2.SamlServiceProvider(CONFIG)

    login_manager = LoginManager()
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        # Load the user.
        return User(user_id)

    @app.route("/sp/login")
    @login_manager.unauthorized_handler
    def sp_login():
        return sp.authenticate(next_url="/")

    @app.route("/sp/acs", methods=["GET", "POST"])
    def sp_acs():
        _assertion_info, redirect = sp.handle_assertion(request)
        # Retrieve the user.
        user = User(_assertion_info["uid"][0])
        # Log in the user.
        login_user(user)
        return redirect

    @app.route("/")
    @login_required
    def hello_world():
        return "<p>Hello, World!</p>"

Identity Provider
=================

.. code-block:: python

    from flask import Flask, request
    import flask_pysaml2

    app = Flask(__name__)
    app.secret_key = "SUPER_SECRET_KEY"
    idp = flask_pysaml2.SamlIdentityProvider(CONFIG)

    @app.route("/idp/sso")
    def idp_sso():
        # Return identity (assuming user is logged in and identity is in the cache)
        return idp.handle_sso_request(request)

    @app.route("/idp/metadata", methods=["GET"])
    def idp_metadata():
        return idp.get_metadata()

Using the Examples in `examples/`
=================================

To run the examples, you'll first need to install a few packages:

.. code-block:: bash

    $ pip install flask-login
    $ pip install pyopenssl

You'll also need a set of certificates (update configs in the code
to point at them):

.. code-block:: bash

    $ openssl req -x509 -newkey rsa:2048 -keyout sso_private.key -out sso_public.crt -days 3650 -nodes

With everything all set up you should be able to run them and access in
a browser at `<https://127.0.0.1:5000/>`__:

.. code-block:: bash

    $ python sp_app.py
    $ python idp_app.py