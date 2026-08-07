import ipaddress


def generate_hostapd_conf(settings: dict, iface: str) -> str:
    s = settings
    lines = [
        f"interface={iface}",
        "driver=nl80211",
        f"ssid={s['ssid']}",
        f"channel={s['channel']}",
        f"country_code={s['country_code']}",
        "ieee80211d=1",
        f"ignore_broadcast_ssid={1 if s['hidden'] else 0}",
        f"max_num_sta={s['max_clients']}",
        f"beacon_int={s['beacon_interval']}",
        f"dtim_period={s['dtim_period']}",
        f"ap_isolate={1 if s['ap_isolate'] else 0}",
        f"preamble={1 if s['short_preamble'] else 0}",
        f"disassoc_low_ack={1 if s['disassoc_low_ack'] else 0}",
    ]
    if s.get("rts_threshold", -1) != -1:
        lines.append(f"rts_threshold={s['rts_threshold']}")
    if s.get("frag_threshold", -1) != -1:
        lines.append(f"fragm_threshold={s['frag_threshold']}")

    if s["band"] == "5":
        lines.append("hw_mode=a")
        lines.append("ieee80211n=1")





    else:
        lines.append("hw_mode=g")
        lines.append("ieee80211n=1")







    sec = s["security"]
    if sec == "open":
        pass
    else:
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

    lines.append("ctrl_interface=/var/run/hostapd")
    lines.append("ctrl_interface_group=0")
    lines.append(f"wmm_enabled={1 if s['wmm_enabled'] else 0}")

    return "\n".join(lines) + "\n"


def generate_dnsmasq_conf(settings: dict, iface: str, lease_file: str, extra_lines=None) -> str:
    s = settings
    network = ipaddress.ip_network(s["ip_range"], strict=False)
    gateway = str(list(network.hosts())[0])
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


    if extra_lines:
        lines.extend(extra_lines)
    return "\n".join(lines) + "\n", gateway
