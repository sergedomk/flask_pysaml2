Flask-PySAML2
=============

This library implements an integration for the Flask web framework to the
PySAML2 library developed by Roland Hedberg.

PySAML2 is licensed under the Apache 2.0 License and is copyrighted as:
 - Copyright (C) 2007 SIOS Technology, Inc.
 - Copyright (C) 2011 Umea Universitet, Sweden

The Flask-PySAML2 library is licensed under the Modified BSD License.
 - Copyright (c) 2012, Kavi Corporation

Documentation
-------------

Complete documentation can be found at https://flask-pysaml2.readthedocs.io/

CHANGES
-------

**Version 2.1**

Release on November 12, 2026

* Minor document fixes to get package and docs aligned
* Version bump

**Version 2.0**

Release on November 12, 2026

* Updated for Python 3.12 (no longer backward compatible to Python 2)
* Updated `pysaml2` to 7.5.5
* Rebuilt certificates for testing (old ones had expired)
* Added readthedocs YAML file
* Moved tests to `pytest`
* Moved linting to `ruff`
* Added usage docs
* Added example SP app

**Version 1.14**

Release on September 12, 2016

* Public release
