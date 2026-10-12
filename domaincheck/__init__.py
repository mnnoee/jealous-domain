"""Пакет domaincheck: диагностика домена (RDAP/whois, DNS, SSL)."""

# Версия берётся из constants.VERSION — единственный источник истины.
# pyproject.toml читает её через [tool.setuptools.dynamic].
from .constants import VERSION as __version__

__all__ = ["__version__"]
