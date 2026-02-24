"""Utility module for XML operations.

This module centralizes the safe and unsafe XML operations to ensure
consistent security boundaries across the application.

Please see security_xml.md for detailed security guidelines on XML parsing.
"""

from xml.etree.ElementTree import Element as UnsafeElement
from xml.etree.ElementTree import SubElement as UnsafeSubElement
from defusedxml.ElementTree import tostring, ParseError
from defusedxml.ElementTree import parse as safe_parse
from defusedxml.ElementTree import fromstring as safe_fromstring
import defusedxml.sax as safe_sax
from defusedxml.common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden

__all__ = [
    "UnsafeElement",
    "UnsafeSubElement",
    "tostring",
    "ParseError",
    "safe_parse",
    "safe_fromstring",
    "safe_sax",
    "DTDForbidden",
    "EntitiesForbidden",
    "ExternalReferenceForbidden",
]
