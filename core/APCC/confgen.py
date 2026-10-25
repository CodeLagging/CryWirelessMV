import ipaddress

# 80MHz / 160MHz segment-0 center-channel index per 5GHz channel group.
# hostapd needs vht_oper_centr_freq_seg0_idx to be the channel number at the
# center of the whole wide channel, not the primary channel.
_VHT80_CENTER = {
    frozenset([36, 40, 44, 48]): 42,
    frozenset([52, 56, 60, 64]): 58,
    frozenset([100, 104, 108, 112]): 106,
    frozenset([116, 120, 124, 128]): 122,
    frozenset([132, 136, 140, 144]): 138,
    frozenset([149, 153, 157, 161]): 155,
}
_VHT160_CENTER = {
    frozenset([36, 40, 44, 48, 52, 56, 60, 64]): 50,
    frozenset([100, 104, 108, 112, 116, 120, 124, 128]): 114,
}


def _center_idx(channel, table):
    for group, center in table.items():
        if channel in group:
            return center
    return None


def _ht40_secondary(band, channel):
    """'+' when the 40MHz secondary channel sits above the primary, '-' below."""
    if band == "2.4":
        return "+" if channel <= 7 else "-"
    # 5GHz channels come in +4 pairs; the lower of each pair extends upward.
    return "+" if ((channel - 36) // 4) % 2 == 0 else "-"


def generate_hostapd_conf(settings: dict, iface: str) -> str:
    s = settings
    width = str(s.get("channel_width", "20"))
    ht = bool(s.get("ht_enabled", True))
    vht = bool(s.get("vht_enabled", False)) and s["band"] == "5"
    he = bool(s.get("he_enabled", False))

    lines = [
        f"interface={iface}",
        "driver=nl80211",
        f"ssid={s['ssid']}",
        f"channel={s['channel']}",
        f"country_code={s['country_code']}",
        f"ieee80211d={1 if s.get('ieee80211d', True) else 0}",
        f"ignore_broadcast_ssid={1 if s['hidden'] else 0}",
        f"utf8_ssid={1 if s.get('utf8_ssid', True) else 0}",
        f"max_num_sta={s['max_clients']}",
        f"ap_max_inactivity={s.get('ap_max_inactivity', 300)}",
        f"beacon_int={s['beacon_interval']}",
        f"dtim_period={s['dtim_period']}",
        f"ap_isolate={1 if s['ap_isolate'] else 0}",
        f"preamble={1 if s['short_preamble'] else 0}",
        f"disassoc_low_ack={1 if s['disassoc_low_ack'] else 0}",
    ]
    if s["band"] == "5" and s.get("ieee80211h"):
        lines.append("ieee80211h=1")
    if s.get("rts_threshold", -1) != -1:
        lines.append(f"rts_threshold={s['rts_threshold']}")
    if s.get("frag_threshold", -1) != -1:
        lines.append(f"fragm_threshold={s['frag_threshold']}")

    lines.append("hw_mode=a" if s["band"] == "5" else "hw_mode=g")

    # --- HT (802.11n) ---
    if ht:
        lines.append("ieee80211n=1")
        caps = []
        if width in ("40", "80", "160"):
            sec = _ht40_secondary(s["band"], int(s["channel"]))
            caps.append("[HT40+]" if sec == "+" else "[HT40-]")
        if s.get("short_gi", True):
            caps.append("[SHORT-GI-20]")
            if width in ("40", "80", "160"):
                caps.append("[SHORT-GI-40]")
        if caps:
            lines.append("ht_capab=" + "".join(caps))
        if s.get("require_ht"):
            lines.append("require_ht=1")

    # --- VHT (802.11ac, 5GHz) ---
    if vht:
        lines.append("ieee80211ac=1")
        chan = int(s["channel"])
        if width == "80":
            idx = _center_idx(chan, _VHT80_CENTER)
            if idx:
                lines.append("vht_oper_chwidth=1")
                lines.append(f"vht_oper_centr_freq_seg0_idx={idx}")
        elif width == "160":
            idx = _center_idx(chan, _VHT160_CENTER)
            if idx:
                lines.append("vht_oper_chwidth=2")
                lines.append(f"vht_oper_centr_freq_seg0_idx={idx}")
        if s.get("short_gi", True):
            lines.append("vht_capab=[SHORT-GI-80]")
        if s.get("require_vht"):
            lines.append("require_vht=1")

    # --- HE (802.11ax) ---
    if he:
        lines.append("ieee80211ax=1")

    sec = s["security"]
    if sec != "open":
        if sec == "wpa2":
            lines.append("wpa=2")
            lines.append("wpa_key_mgmt=WPA-PSK")
        elif sec == "wpa3":
            lines.append("wpa=2")
            lines.append("wpa_key_mgmt=SAE")
        elif sec == "wpa2/wpa3":
            lines.append("wpa=2")
            lines.append("wpa_key_mgmt=WPA-PSK SAE")

        lines.append(f"wpa_passphrase={s['psk']}")

        cipher_map = {"ccmp": "CCMP", "tkip": "TKIP", "ccmp+tkip": "CCMP TKIP"}
        lines.append(f"rsn_pairwise={cipher_map.get(s['cipher'], 'CCMP')}")

        pmf_map = {"disabled": "0", "optional": "1", "required": "2"}
        lines.append(f"ieee80211w={pmf_map.get(s['pmf'], '1')}")

        if s["sae"]:
            lines.append("sae_require_mfp=1")
        if int(s.get("wpa_group_rekey", 0) or 0) > 0:
            lines.append(f"wpa_group_rekey={int(s['wpa_group_rekey'])}")
        if int(s.get("wpa_ptk_rekey", 0) or 0) > 0:
            lines.append(f"wpa_ptk_rekey={int(s['wpa_ptk_rekey'])}")
        if s.get("okc"):
            lines.append("okc=1")

    lines.append("ctrl_interface=/var/run/hostapd")
    lines.append("ctrl_interface_group=0")
    # accept-unless-denied: lets 'client <mac> block' add runtime deny-ACL
    # entries (hostapd_cli deny_acl ADD_MAC) that are honored on association.
    lines.append("macaddr_acl=0")
    lines.append(f"wmm_enabled={1 if s['wmm_enabled'] else 0}")

    return "\n".join(lines) + "\n"


def generate_dnsmasq_conf(settings: dict, iface: str, lease_file: str,
                          extra_lines=None, mtu=0, upstream_dns=None) -> str:
    s = settings
    network = ipaddress.ip_network(s["ip_range"], strict=False)
    gateway = str(next(iter(network.hosts())))
    lines = [
        f"interface={iface}",
        "bind-interfaces",
        "except-interface=lo",
        f"dhcp-range={s['dhcp_start']},{s['dhcp_end']},{s['dhcp_lease_time']}",
        f"dhcp-option=3,{gateway}",
        f"dhcp-option=6,{gateway}",
        "dhcp-authoritative",
        f"dhcp-leasefile={lease_file}",
        "log-queries",
        "log-dhcp",
    ]

    # Option 26 (interface-mtu): cap client MTU to the real uplink path so
    # large UDP (and any client ignoring TCP MSS) stays under it instead of
    # blackholing on a smaller upstream link.
    try:
        mtu = int(mtu)
    except (TypeError, ValueError):
        mtu = 0
    if mtu and mtu < 1500:
        lines.append(f"dhcp-option=26,{mtu}")

    domain = (s.get("dhcp_domain") or "").strip()
    if domain:
        lines.append(f"domain={domain}")
        lines.append(f"dhcp-option=15,{domain}")

    # Keep upstream resolution self-contained: when we know where to forward,
    # set it explicitly and stop reading the host's /etc/resolv.conf, so the
    # generated config is portable and doesn't depend on host DNS state.
    servers = [s for s in (upstream_dns or []) if s]
    if servers:
        lines.append("no-resolv")
        lines.extend(f"server={s}" for s in servers)

    if extra_lines:
        lines.extend(extra_lines)
    return "\n".join(lines) + "\n", gateway
