import logging

from saml2.config import config_factory
from saml2.md import KeyDescriptor
from saml2.metadata import do_key_descriptor, entity_descriptor

LOGGER = logging.getLogger(__name__)


def _parse_key_descriptors(certs: list[dict]) -> list[KeyDescriptor]:
    """Creates the PySAML2 key descriptor for inclusion in a metadata object.

    Args:
        certs (list): Config information about the certificates and how they
            are used.

    Returns:
        (list): key descriptors for all configured certs.
    """
    key_descriptors = []
    for _cert in certs:
        _cdata = _cert.get("cert_data") or "".join(
            open(_cert.get("cert_file")).readlines()[1:-1]
        )
        key_descriptors.extend(
            do_key_descriptor(_cdata, _cdata, _cert.get("use", "both"))
        )
    return key_descriptors


def parse_metadata_dict_to_inline(metadata: dict, typ: str) -> dict:
    """Convert any metadata included as dict to PySAML2's `inline` type.

    Currently, PySAML supports remote, local files, and string IdP/SP metadata to
    be included in the SP/IdP config dict as XML. It is also possible to pull your
    IdP metadata from local JSON files (the format of the JSON is nearly
    unparsable for any normal human).

    This function adds the ability to include the IdP/SP metadata directly in the
    SP config as a dict of IdP attributes by hacking around this PySAML2
    limitation and converting the dict into XML via PySAML2's IdPConfig class.

    Note: In the process of trying to find an alternative which will allow us
        to NOT be hacking around PySAML so rudely in order to load IdP metadata
        from a Python dict. https://github.com/rohe/pysaml2/issues/172

    Args:
        metadata (dict): The IdP/SP metadata this SP/IdP is configured for.
        typ (str): Whether we are getting metadata for an SP or IdP service.

    Returns:
        (dict) config where any metadata `inline_dict` data has been
            converted to `inline` XML.
    """
    if metadata.get("inline_dict") is not None:
        metadata["inline"] = metadata.get("inline", [])
        for _config_dict in metadata.get("inline_dict", []):
            _config = config_factory(typ, _config_dict)
            entity_desc = entity_descriptor(_config)
            # Hack for supporting multiple certificates.
            if _config_dict.get("certs"):
                # `certs` config directive overrides `cert_file`.
                if typ == "sp":
                    entity_desc.idpsso_descriptor.key_descriptor = (
                        _parse_key_descriptors(_config_dict["certs"])
                    )
                else:
                    entity_desc.spsso_descriptor.key_descriptor = (
                        _parse_key_descriptors(_config_dict["certs"])
                    )
            _metadata_str = str(entity_desc)
            LOGGER.debug(
                "IdP XML Metadata for %s: %s", _config_dict["entityid"], _metadata_str
            )
            metadata["inline"].append(_metadata_str)
        del metadata["inline_dict"]
    return metadata
