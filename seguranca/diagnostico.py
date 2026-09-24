"""Consultas de leitura; nunca altera politicas do computador."""
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCRIPT = r"""+$ErrorActionPreference = 'Stop'
$result = @{defender=@{status='unknown'}; firewall=@{status='unknown'}}
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  $result.defender = @{status='observed'; antivirus_enabled=$mp.AntivirusEnabled;
    realtime_enabled=$mp.RealTimeProtectionEnabled;
    signatures_outdated=$mp.DefenderSignaturesOutOfDate}
} catch { $result.defender = @{status='unavailable'} }
try {
  $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
  $result.firewall = @{status='observed'; profile_count=$profiles.Count;
    enabled_count=@($profiles | Where-Object {$_.Enabled -eq $true}).Count}
} catch { $result.firewall = @{status='unavailable'} }
$result | ConvertTo-Json -Depth 4 -Compress
"""


def normalize(raw):
    """Whitelist and type-check fields. No hostnames, IPs or usernames escape."""
    result = {}
    for name in ("defender", "firewall"):
        item = raw.get(name, {}) if isinstance(raw, dict) else {}
        if not isinstance(item, dict) or item.get("status") != "observed":
            result[name] = {"status": "unavailable"}
            continue
        if name == "defender":
            fields = ("antivirus_enabled", "realtime_enabled", "signatures_outdated")
            result[name] = {"status": "observed"}
            for field in fields:
                result[name][field] = item.get(field) if type(item.get(field)) is bool else None
        else:
            count, enabled = item.get("profile_count"), item.get("enabled_count")
            if type(count) is int and type(enabled) is int and 0 <= enabled <= count <= 10 and count > 0:
                result[name] = {"status": "observed", "profile_count": count, "enabled_count": enabled}
            else:
                result[name] = {"status": "unavailable"}
    return result


def collect():
    result = {"collected_at": datetime.now(timezone.utc).isoformat(),
              "defender": {"status": "unavailable"}, "firewall": {"status": "unavailable"}}
    if os.name != "nt":
        result["note"] = "Diagnostico disponivel apenas no Windows."
        return result
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    exe = root / "System32/WindowsPowerShell/v1.0/powershell.exe"
    native = root / "Sysnative/WindowsPowerShell/v1.0/powershell.exe"
    if native.exists():
        exe = native
    try:
        response = subprocess.run([str(exe), "-NoProfile", "-NonInteractive", "-Command", SCRIPT],
                                  capture_output=True, timeout=25, check=True,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        result.update(normalize(json.loads(response.stdout.decode("utf-8-sig"))))
    except (OSError, subprocess.SubprocessError, ValueError):
        result["note"] = "Consulta indisponivel ou excedeu 25 segundos. Estado nao verificado."
    return result


def explain(result):
    lines = ["Diagnostico de leitura. Nao e uma analise de malware.",
             "Recolhido: " + result.get("collected_at", "nao verificado")]
    data = normalize(result)
    defender = data["defender"]
    if defender["status"] != "observed":
        lines.append("Defender: nao foi possivel verificar. Outro antivirus pode estar ativo.")
    else:
        labels = {"antivirus_enabled": "Antivirus Defender ativo",
                  "realtime_enabled": "Defender em tempo real",
                  "signatures_outdated": "Assinaturas Defender desatualizadas"}
        for field, label in labels.items():
            value = defender.get(field)
            lines.append(label + ": " + ("sim" if value is True else "nao" if value is False else "desconhecido"))
        if defender.get("realtime_enabled") is False:
            lines.append("Rever na Seguranca do Windows; modo passivo com outro motor e possivel.")
    firewall = data["firewall"]
    if firewall["status"] == "observed":
        lines.append(f"Firewall: {firewall['enabled_count']}/{firewall['profile_count']} perfis ativados.")
        lines.append("Isto nao identifica o perfil atual nem verifica todas as regras da rede.")
    else:
        lines.append("Firewall: nao foi possivel verificar.")
    lines.append("Conta Google: nao observada automaticamente por esta aplicacao.")
    return "\n".join(lines)
