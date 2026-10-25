# core/WIFI/attack_module.py
"""Compatibility wrapper for per-attack modules."""

from .action_frame import action_frame_flood
from .ap_flood import access_point_flood
from .auth_dos import auth_dos
from .bad_message import bad_message_flood, bad_message_targeted
from .csa_attack import flood_csa, targeted_csa
from .deauth import deauth_all
from .disassoc import disassoc_all
from .michael_mic import michael_mic_dos
from .probe_dos import probe_dos
from .quiet_device import quiet_flood, quiet_targeted


class AttackModule:
    deauth_all = staticmethod(deauth_all)
    auth_dos = staticmethod(auth_dos)
    disassoc_all = staticmethod(disassoc_all)
    access_point_flood = staticmethod(access_point_flood)
    michael_mic_dos = staticmethod(michael_mic_dos)
    probe_dos = staticmethod(probe_dos)
    flood_csa = staticmethod(flood_csa)
    targeted_csa = staticmethod(targeted_csa)
    action_frame_flood = staticmethod(action_frame_flood)
    bad_message_flood = staticmethod(bad_message_flood)
    bad_message_targeted = staticmethod(bad_message_targeted)
    quiet_flood = staticmethod(quiet_flood)
    quiet_targeted = staticmethod(quiet_targeted)