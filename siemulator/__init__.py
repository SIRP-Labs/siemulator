"""siemulator — synthetic SIEM endpoints in real-vendor shapes.

Two parallel mock surfaces from one template pool:

  /logscale/*  — Falcon LogScale shape (Humio REST API)
  /qradar/*    — QRadar shape (offences + Ariel searches)

Mount points are configurable via SIEMULATOR_LOGSCALE_PREFIX /
SIEMULATOR_QRADAR_PREFIX env vars (set to /omnisense for sara-open
drop-in compatibility).
"""

__version__ = "0.1.0"

from siemulator.app import create_app

__all__ = ["create_app", "__version__"]
