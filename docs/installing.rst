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
