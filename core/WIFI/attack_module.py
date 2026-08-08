# core/WIFI/attack_module.py
"""Compatibility wrapper for per-attack modules."""

from .deauth import deauth_all
from .auth_dos import auth_dos
from .ap_flood import access_point_flood
from .michael_mic import michael_mic_dos
from .probe_dos import probe_dos

class AttackModule:
    deauth_all = staticmethod(deauth_all)
    auth_dos = staticmethod(auth_dos)
    access_point_flood = staticmethod(access_point_flood)
    michael_mic_dos = staticmethod(michael_mic_dos)
    probe_dos = staticmethod(probe_dos)
