from setuptools import setup

with open("README.rst") as fd:
    readme = fd.read()

with open("requirements.txt") as f:
    requirements = f.readlines()
    install_requires = [line for line in requirements if not line.startswith("#")]

with open("requirements-testing.txt") as f:
    test_reqs = f.readlines()
    tests_require = [line for line in test_reqs if not line.startswith("#")]

setup(
    name="Flask-Pysaml2",
    version="2.0",
    url="https://github.com/sergedomk/flask_pysaml2",
    licence="BSD",
    author="Serge Domkowski (orig. Kavi Corporation)",
    author_email="sergedomk@gmail.com",
    description="Flask and pysaml2 integration.",
    long_description=readme,
    py_modules=["flask_pysaml2"],
    include_package_data=True,
    platform="any",
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
    ],
    keywords="flask,pysaml2,saml2,federated authentication,authentication",
    install_requires=install_requires,
    tests_require=tests_require,
)
