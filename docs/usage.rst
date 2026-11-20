Using ``flask_pysaml2`` in your Flask app
-----------------------------------------

Flask-pysaml2 uses the same config as pysaml2
(`<https://pysaml2.readthedocs.io/en/latest/howto/config.html>`__)
with two notable additions. To facilitate dynamically configured IPDs,
we've added an `inline_dict` for metadata. We, also, added the ability
to have multiple certificates for an inline IDP.

Below is a rather simplified example of using in a Flask app. The
`examples` folder includes a more complete example.

.. code-block:: python

    from flask import Flask, request
    import flask_pysaml2

    app = Flask(__name__)
    app.secret_key = "SUPER_SECRET_KEY"
    sp = flask_pysaml2.SamlServiceProvider(CONFIG)

    @app.route("/sp/login")
    def sp_login():
        return sp.authenticate(next_url="/")

    @app.route("/sp/acs", methods=["GET", "POST"])
    def sp_acs():
        _assertion_info, redirect = sp.handle_assertion(request)
        # Do something with the assertion info (includes identity)
        return redirect