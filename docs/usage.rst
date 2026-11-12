What is SAML?
-------------

The OASIS Security Assertion Markup Language (SAML) is an XML-based
framework for describing and exchanging security information. SAML
provides Federated Identity and Single Sign-On support for businesses.

`<https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#1.Introduction|outline>`__

Installing ``flask_pysaml2``
----------------------------

**From PyPi**

.. code-block:: bash

    $ pip install flask-pysaml2

**From source (tar.gz or checkout)**

Unpack the archive, entry the ``flask_pysaml2`` directory and run:

.. code-block:: bash

    $ python setup.py install

Prerequisites
^^^^^^^^^^^^^

``flask_pysaml2`` provides support to use the ``pysaml2`` library
in a Flask application. As such, ``pysaml2`` is a requirement along
with its prerequisites. Please refer to the ``pysaml2`` installation
documentation `<https://pysaml2.readthedocs.io>`__ for ``pysaml2``
prerequisites.

You will also need a set of certificates in order to sign and encrypt
requests and responses.

.. code-block:: bash

    $ openssl req -x509 -newkey rsa:2048 -keyout sso_private.key -out sso_public.crt -days 3650 -nodes

Using ``flask_pysaml2`` in your Flask app
-----------------------------------------

Flask-pysaml2 uses the same config as pysaml2
(`<https://pysaml2.readthedocs.io/en/latest/howto/config.html>`__)
with one notable addition. To facilitate dynamically configured IPDs,
we've added an `inline_dict` for metadata.

Below is a rather simplified example of using in a Flask app. The
`examples` folder includes a more complete example.

.. code-block:: python

    from flask import Flask, request
    import flask_pysaml2

    app = Flask(__name__)
    app.secret_key = "SUPER_SECRET_KEY"
    sp = flask_pysaml2.Saml(CONFIG)

    @app.route("/sp/login")
    def sp_login():
        return sp.authenticate(next_url="/")

    @app.route("/sp/acs", methods=["GET", "POST"])
    def sp_acs():
        _assertion_info, redirect = sp.handle_assertion(request)
        # Do something with the assertion info (includes identity)
        return redirect