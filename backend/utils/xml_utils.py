"""Utility module for XML operations.

This module centralizes the safe and unsafe XML operations to ensure
consistent security boundaries across the application.

Please see security_xml.md for detailed security guidelines on XML parsing.
"""

from xml.etree.ElementTree import Element as UnsafeElement
from xml.etree.ElementTree import SubElement as UnsafeSubElement

import defusedxml.sax as _safe_sax
from defusedxml.common import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
)
from defusedxml.ElementTree import ParseError
from defusedxml.ElementTree import fromstring as safe_fromstring
from defusedxml.ElementTree import parse as safe_parse
from defusedxml.ElementTree import tostring

# NOTE: UnsafeElement and UnsafeSubElement are the standard ElementTree
# constructors. They are aliased here with 'Unsafe' prefix to remind developers
# that they must ONLY be used for XML generation, never for parsing untrusted data.
# For parsing, use the safe_* functions provided below.


def safe_sax_parse_string(xml_string, handler, **kwargs):
    """
    Safely parses an XML string using SAX.
    Wraps defusedxml.sax.parseString to provide a consistent project interface.
    """
    return _safe_sax.parseString(xml_string, handler, **kwargs)


__all__ = [
    "UnsafeElement",
    "UnsafeSubElement",
    "tostring",
    "ParseError",
    "safe_parse",
    "safe_fromstring",
    "safe_sax_parse_string",
    "DTDForbidden",
    "EntitiesForbidden",
    "ExternalReferenceForbidden",
]
