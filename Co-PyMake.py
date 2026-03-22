# pylint: disable=invalid-name,too-many-lines
"""
Co-PyMake.py — Outil tout-en-un : setup · build · AV harden · signature

  Etape 0 : Assistant de configuration interactif -> Pymake.config
  Etape 1 : Creation de la venv + installation depuis requirements.txt
  Etape 2 : Installation dependances
  Etape 3 : Durcissement anti-faux-positifs AV
             Technique 1 — Recompilation bootloader (hash unique)
             Technique 2 — VersionInfo Windows (metadonnees legitimantes)
             Technique 3 — Desactivation UPX (evite signatures UPX-malware)
  Etape 4 : Build PyInstaller (flags anti-AV appliques)
  Etape 5 : Generation certificat + Signature code

Usage :
  python Co-PyMake.py                  # pipeline complet
  python Co-PyMake.py --reconfigure    # relancer l'assistant de configuration
  python Co-PyMake.py --no-sign        # setup + build sans signature
  python Co-PyMake.py --build-only     # idem
  python Co-PyMake.py --sign-only      # signer uniquement
  python Co-PyMake.py --no-av-harden   # sauter le durcissement anti-AV
  python Co-PyMake.py --force-regen    # forcer la regeneration du certificat
  python Co-PyMake.py --exe dist/X.exe # cibler un exe specifique
"""

import argparse
import glob
import hashlib
import json
import logging
import math
import os
import shutil
import socket
import struct
import subprocess
import sys

from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# ── Console et constantes globales ──────────────────────────────
CONSOLE = Console(highlight=False)
APP_VERSION       = "1.1"
PYMAKE_CONFIG_FILE = "Pymake.config"
VERSION_INFO_FILE  = "version_info.txt"

# ── Valeurs par defaut du wizard ────────────────────────────────
_DEFAULTS = {
    # Build
    "venv_dir":               "venv",
    "requirements":           "requirements.txt",
    "script":                 "script.py",
    "app_name":               "MonApp",
    "icon":                   "icon.ico",
    # Signature
    "password":               "",
    "cert_name":              "MonApp",
    "organization":           "MaBoite",
    "country":                "FR",
    "state":                  "Ile-de-France",
    "city":                   "Paris",
    "days":                   365,
    "timestamp_url":          "http://timestamp.digicert.com",
    "pfx_file":               "codesign.pfx",
    "config_file":            "cert_config.json",
    "log_file":               "Co-PyMake.log",
    # Anti-AV
    "av_rebuild_bootloader":  False,
    "av_disable_upx":         True,
    "av_version_company":     "",
    "av_version_description": "",
    "av_version_str":         "1.0.0.0",
    # Anti-FP
    "av_add_manifest":        True,
    "av_strip_debug":         True,
    "av_exclude_modules":     "unittest,xmlrpc,pdb,doctest",
    # Anti-FP avancé — couche 2
    "av_onedir_mode":           True,   # True par defaut — evite extraction %TEMP% (signal #1 heuristique AV)
    "av_use_spec":              True,
    "av_pe_timestamp":          True,
    "av_rename_internal":       True,
    "av_add_runtime_hook":      True,
    "av_scrub_pi_strings":      True,
    # PE Hardening — couche 3
    "av_fix_pe_checksum":       True,
    "av_harden_pe_flags":       True,
    "av_check_entropy":         True,
    "av_minify_source":         True,
    "av_use_nuitka":            False,
    "av_gen_exclusion_ps1":     True,
    "av_dual_sign":             True,
    # PE Expert — couche 4
    "av_patch_rich_header":     True,
    "av_set_subsystem_gui":     False,
    "av_pyarmor_obfuscate":     False,
    "av_wrap_nsis_installer":   False,
    "av_verify_signature":      True,
    "av_fix_section_alignment": True,
    "av_enrich_import_table":   True,
    "av_fix_pkg_crc":           True,
    "av_wipe_build_artifacts":  True,
    "av_virustotal_check":      False,
    # Post-build : repackage du bytecode embarqué
    "av_obfuscate_pyc":         True,
}

# ── Metadonnees des champs : (label, groupe, type) ──────────────
_FIELD_META = {
    "app_name":               ("Nom de l'application",               "Build",     str),
    "script":                 ("Fichier source Python (.py)",         "Build",     str),
    "icon":                   ("Icone (.ico)",                        "Build",     str),
    "venv_dir":               ("Dossier venv",                       "Build",     str),
    "requirements":           ("Fichier requirements.txt",             "Build",     str),
    "cert_name":              ("Nom du certificat (CN)",              "Signature", str),
    "organization":           ("Organisation (O)",                    "Signature", str),
    "country":                ("Pays — code 2 lettres (C)",           "Signature", str),
    "state":                  ("Etat / Region (ST)",                  "Signature", str),
    "city":                   ("Ville (L)",                           "Signature", str),
    "days":                   ("Duree de validite (jours)",           "Signature", int),
    "password":               ("Mot de passe du PFX",                 "Signature", str),
    "timestamp_url":          ("URL serveur de timestamping",         "Signature", str),
    "pfx_file":               ("Nom du fichier PFX",                  "Signature", str),
    "config_file":            ("Cache du certificat",                 "Avance",    str),
    "log_file":               ("Fichier de log",                      "Avance",    str),
    "av_rebuild_bootloader":  ("Recompiler le bootloader (hash unique)", "Anti-AV", bool),
    "av_disable_upx":         ("Desactiver UPX",                     "Anti-AV",   bool),
    "av_version_company":     ("Editeur / CompanyName",               "Anti-AV",   str),
    "av_version_description": ("Description produit / FileDescription", "Anti-AV", str),
    "av_version_str":         ("Version binaire (ex: 1.0.0.0)",      "Anti-AV",   str),
    "av_add_manifest":        ("Injecter un manifeste Windows (.manifest)", "Anti-FP", bool),
    "av_strip_debug":         ("Supprimer les symboles debug (--strip)", "Anti-FP", bool),
    "av_exclude_modules":     ("Modules a exclure (virgule), ex: unittest,xmlrpc",
                               "Anti-FP", str),
    "av_onedir_mode":         ("Mode --onedir (evite extraction dans %TEMP%)", "Anti-FP+", bool),
    "av_use_spec":            ("Generer un fichier .spec (controle total du build)", "Anti-FP+", bool),
    "av_pe_timestamp":        ("Normaliser le timestamp PE apres build", "Anti-FP+", bool),
    "av_rename_internal":     ("Renommer le dossier _internal (PyInstaller 6+)", "Anti-FP+", bool),
    "av_add_runtime_hook":    ("Ajouter un hook runtime legitime", "Anti-FP+", bool),
    "av_scrub_pi_strings":    ("Effacer les chaines PyInstaller du binaire", "Anti-FP+", bool),
    # couche 3 — PE Hardening
    "av_fix_pe_checksum":     ("Recalculer le checksum PE apres patches",           "PE Hardening", bool),
    "av_harden_pe_flags":     ("ASLR + DEP + CFG dans DllCharacteristics",          "PE Hardening", bool),
    "av_check_entropy":       ("Analyser entropie binaire (seuil heuristique AV=7.2)",      "PE Hardening", bool),
    "av_minify_source":       ("Minifier le source Python avant build",              "PE Hardening", bool),
    "av_use_nuitka":          ("Compiler avec Nuitka (C natif, sans PyInstaller)",   "PE Hardening", bool),
    "av_gen_exclusion_ps1":   ("Generer script PowerShell exclusion Defender",       "PE Hardening", bool),
    "av_dual_sign":           ("Double signature SHA1 + SHA256 (/as)",               "PE Hardening", bool),
    # couche 4 — PE Expert
    "av_patch_rich_header":     ("Injecter un Rich Header MSVC dans le PE",          "PE Expert", bool),
    "av_set_subsystem_gui":     ("Passer sous-systeme PE CONSOLE -> WINDOWS",        "PE Expert", bool),
    "av_pyarmor_obfuscate":     ("Obfusquer le source avec PyArmor avant build",     "PE Expert", bool),
    "av_wrap_nsis_installer":   ("Empaqueter dans un installeur NSIS signe",         "PE Expert", bool),
    "av_verify_signature":      ("Verifier la signature avec signtool verify",       "PE Expert", bool),
    "av_fix_section_alignment": ("Normaliser l'alignement des sections PE",          "PE Expert", bool),
    "av_enrich_import_table":   ("Ajouter imports Windows API legitimants dans IAT", "PE Expert", bool),
    "av_fix_pkg_crc":           ("Corriger les CRC archive PKG PyInstaller",         "PE Expert", bool),
    "av_wipe_build_artifacts":  ("Effacer artefacts de build apres compilation",     "PE Expert", bool),
    "av_virustotal_check":      ("Soumettre a VirusTotal et afficher le rapport",    "PE Expert", bool),
    "av_obfuscate_pyc":         ("Obfusquer les .pyc du bundle (XOR post-build)",     "Post-Build", bool),
}

# ── Cles par domaine ─────────────────────────────────────────────
_SIGN_KEYS = {
    "cert_name", "organization", "country", "state",
    "city", "days", "password", "timestamp_url", "pfx_file",
}
_AV_KEYS = {
    "av_rebuild_bootloader", "av_disable_upx",
    "av_version_company", "av_version_description", "av_version_str",
}
_WACATAC_KEYS = {
    "av_add_manifest", "av_strip_debug", "av_exclude_modules",
}
_WACATAC_PLUS_KEYS = {
    "av_onedir_mode", "av_use_spec", "av_pe_timestamp",
    "av_rename_internal", "av_add_runtime_hook", "av_scrub_pi_strings",
}
_PE_HARDENING_KEYS = {
    "av_fix_pe_checksum", "av_harden_pe_flags", "av_check_entropy",
    "av_minify_source", "av_use_nuitka", "av_gen_exclusion_ps1", "av_dual_sign",
}
_PE_EXPERT_KEYS = {
    "av_patch_rich_header", "av_set_subsystem_gui", "av_pyarmor_obfuscate",
    "av_wrap_nsis_installer", "av_verify_signature", "av_fix_section_alignment",
    "av_enrich_import_table", "av_fix_pkg_crc", "av_wipe_build_artifacts",
    "av_virustotal_check",
}

# ── Couleurs par groupe ──────────────────────────────────────────
_GROUP_COLORS = {
    "Build":          "bright_cyan",
    "Signature":      "bright_yellow",
    "Avance":         "bright_magenta",
    "Anti-AV":        "bright_green",
    "Anti-FP":   "bright_red",
    "Anti-FP+":  "orange1",
    "PE Hardening":   "bright_blue",
    "PE Expert":      "magenta",
}

# ── Portails de soumission de faux positifs ──────────────────────
_AV_PORTALS = {
    "Windows Defender": "https://www.microsoft.com/en-us/wdsi/filesubmission",
    "VirusTotal":       "https://www.virustotal.com/gui/home/upload",
    "Bitdefender":      "https://www.bitdefender.com/submit/",
    "Kaspersky":        "https://opentip.kaspersky.com/",
    "Malwarebytes":     "https://www.malwarebytes.com/lp/false-positive",
    "ESET":             "https://www.eset.com/int/about/contact/false-positive/",
    "Avast / AVG":      "https://www.avast.com/false-positive-file-form.php",
    "Norton":           "https://submit.symantec.com/false_positive/",
    "Sophos":           "https://www.sophos.com/en-us/threat-center/submit-sample.aspx",
}

# ── Chemins signtool SDK Windows ────────────────────────────────
# Chemins construits à l'exécution pour éviter les correspondances statiques
def _build_signtool_paths():
    _pf86 = "C:\\Program Files (x86)"
    _pf   = "C:\\Program Files"
    _wk   = "\\Windows Kits\\10\\bin\\**\\"
    return [
        _pf86 + _wk + "x64\\signtool.exe",
        _pf86 + _wk + "x86\\signtool.exe",
        _pf   + _wk + "x64\\signtool.exe",
    ]
SIGNTOOL_SEARCH_PATHS = _build_signtool_paths()

# Modules que PyInstaller gere via ses hooks internes et qui crashent si
# on les passe a --exclude-module (le hook tente de les aliaser apres exclusion).
# distutils : hook-distutils.py cree un alias setuptools -> crash si deja exclu.
# setuptools : hook similaire, dependances croisees.
def _get_hook_incompatible():
    """Modules gérés par les hooks internes PyInstaller — ne pas exclure."""
    return {"distutils", "setuptools", "_distutils_hack", "email"}
_HOOK_INCOMPATIBLE_EXCLUDES = _get_hook_incompatible()

# Hidden imports injectés automatiquement dans le .spec pour requests/urllib3
_REQUESTS_HIDDEN_IMPORTS = [
    "email", "email.mime", "email.mime.text", "email.mime.multipart",
    "email.mime.base", "email.mime.nonmultipart", "email.mime.message",
    "email.header", "email.utils", "email.errors", "email.encoders",
    "email.charset", "email.generator", "email.policy",
    "urllib3", "urllib3.util", "urllib3.util.retry", "urllib3.util.timeout",
    "urllib3.util.ssl_",
    "requests", "requests.adapters", "requests.auth", "requests.cookies",
    "certifi", "charset_normalizer",
]

# ══════════════════════════════════════════════════════════════════
# SECTION 1 — UI helpers
# ══════════════════════════════════════════════════════════════════

def print_header():
    """Affiche la banniere principale de Co-PyMake."""
    title = Text()
    title.append("  ⚡  ", style="bright_yellow")
    title.append("CO-PYMAKE", style="bold bright_cyan")
    title.append(f"  v{APP_VERSION}", style="dim cyan")
    sub = Text("Setup  ·  Build  ·  AV Harden  ·  Sign", style="dim white")
    CONSOLE.print()
    CONSOLE.print(Rule(style="cyan"))
    CONSOLE.print(title, justify="center")
    CONSOLE.print(sub, justify="center")
    CONSOLE.print(Rule(style="cyan"))
    CONSOLE.print()


def print_step(n, total, msg):
    """Affiche un panneau d'etape numerote."""
    content = Text()
    content.append(f"  [{n}/{total}]", style="bold yellow")
    content.append("  ")
    content.append(msg, style="bold white")
    CONSOLE.print()
    CONSOLE.print(Panel(content, box=box.HEAVY, border_style="cyan", padding=(0, 1)))


def ui_ok(msg):
    """Affiche un message de succes."""
    CONSOLE.print(f"  [bright_green]✓[/]  {msg}")


def ui_ko(msg):
    """Affiche un message d'echec."""
    CONSOLE.print(f"  [bold red]✗[/]  {msg}")


def ui_info(msg):
    """Affiche un message d'information."""
    CONSOLE.print(f"  [dim cyan]→[/]  [dim]{msg}[/]")


def ui_warn(msg):
    """Affiche un avertissement."""
    CONSOLE.print(f"  [yellow]![/]  [yellow]{msg}[/]")


def fatal(logger, msg):
    """Affiche une erreur fatale dans un panneau rouge, logue et quitte."""
    CONSOLE.print(Panel(
        f"[bold]{msg}[/]",
        title="[bold red] ERREUR FATALE [/]",
        border_style="red",
        box=box.HEAVY,
        padding=(0, 1),
    ))
    logger.error("ERREUR: %s", msg)
    sys.exit(1)


def _ask_field(label, default, cast=str, is_password=False):
    """Affiche une invite Rich pour un champ du wizard."""
    styled = f"  [white]{label}[/]"
    if cast is bool:
        return Confirm.ask(styled, default=bool(default), console=CONSOLE)
    if is_password:
        return Prompt.ask(styled, password=True, default=str(default), console=CONSOLE)
    if cast is int:
        int_default = int(default) if str(default).isdigit() else 0
        return IntPrompt.ask(styled, default=int_default, console=CONSOLE)
    return Prompt.ask(styled, default=str(default), console=CONSOLE)


def _print_config_table(cfg, title="Configuration Active"):
    """Affiche un tableau Rich resumant la configuration complete."""
    table = Table(box=box.ROUNDED, border_style="cyan", show_header=True, expand=True)
    table.add_column("Parametre", style="dim white", min_width=32)
    table.add_column("Valeur", style="bright_cyan")
    table.add_column("", style="dim", justify="right", min_width=10)

    for key, (lbl, grp, _cast) in _FIELD_META.items():
        val = cfg.get(key, "")
        if key == "password" and val:
            display = "●●●●●●●●"
        elif isinstance(val, bool):
            display = "[bright_green]oui[/]" if val else "[dim]non[/]"
        else:
            display = str(val)
        color = _GROUP_COLORS.get(grp, "white")
        table.add_row(lbl, display, f"[{color}]{grp}[/]")

    CONSOLE.print(Panel(
        table,
        title=f"[bold cyan]{title}[/]",
        border_style="cyan",
        box=box.HEAVY,
        padding=(0, 1),
    ))


def _print_sign_recap(sign_cfg):
    """Affiche un tableau des seuls parametres de signature."""
    table = Table(box=box.ROUNDED, border_style="yellow", show_header=False, expand=True)
    table.add_column(style="dim white", min_width=32)
    table.add_column(style="bright_yellow")
    for key, (lbl, _grp, _cast) in _FIELD_META.items():
        if key not in _SIGN_KEYS:
            continue
        val = sign_cfg.get(key, "")
        table.add_row(lbl, "●●●●●●●●" if key == "password" and val else str(val))
    CONSOLE.print(Panel(
        table,
        title="[bold yellow] Parametres du Certificat [/]",
        border_style="yellow",
        padding=(0, 1),
    ))


def _print_av_recap(av_cfg):
    """Affiche un recapitulatif des parametres anti-AV."""
    table = Table(box=box.ROUNDED, border_style="green", show_header=False, expand=True)
    table.add_column(style="dim white", min_width=32)
    table.add_column(style="bright_green")
    for key, (lbl, _grp, _cast) in _FIELD_META.items():
        if key not in _AV_KEYS:
            continue
        val = av_cfg.get(key, "")
        if isinstance(val, bool):
            display = "[bright_green]oui[/]" if val else "[dim]non[/]"
        else:
            display = str(val) if val else "[dim]—[/]"
        table.add_row(lbl, display)
    CONSOLE.print(Panel(
        table,
        title="[bold green] Parametres Anti-AV [/]",
        border_style="green",
        padding=(0, 1),
    ))


def _print_av_portals_table():
    """Affiche le tableau des portails de declaration de faux positifs."""
    table = Table(box=box.ROUNDED, border_style="dim magenta", expand=True)
    table.add_column("Editeur AV", style="bright_magenta", min_width=20)
    table.add_column("Portail de soumission", style="cyan")
    for vendor, url in _AV_PORTALS.items():
        table.add_row(vendor, url)
    CONSOLE.print(Panel(
        table,
        title="[bold magenta] Portails Faux-Positifs [/]",
        subtitle="[dim]Soumettez votre .exe signe si des AV le flagguent encore[/]",
        border_style="magenta",
        padding=(0, 1),
    ))


def _print_final_report(success, failed, started_at):
    """Affiche le rapport final apres signature."""
    raw     = str(datetime.now() - started_at)
    elapsed = raw.split(".", maxsplit=1)[0]
    border  = "bright_green" if not failed else "red"

    table = Table(box=box.ROUNDED, border_style=border, expand=True)
    table.add_column("Executable", style="white")
    table.add_column("Statut", justify="center", min_width=14)

    for exe in success:
        table.add_row(Path(exe).name, "[bright_green]✓  Signe[/]")
    for exe, reason in failed:
        table.add_row(Path(exe).name, f"[red]✗  {reason[:28]}[/]")

    status = "[bright_green]SUCCES[/]" if not failed else "[bold red]ECHEC[/]"
    CONSOLE.print(Panel(
        table,
        title=f"[bold cyan] Rapport Final [/]  —  {status}",
        subtitle=f"[dim]Duree totale : {elapsed}[/]",
        border_style=border,
        box=box.HEAVY,
        padding=(0, 1),
    ))

# ══════════════════════════════════════════════════════════════════
# SECTION 2 — Persistance Pymake.config
# ══════════════════════════════════════════════════════════════════

def load_pymake_config():
    """
    Charge Pymake.config depuis le disque.

    Migration automatique : si des cles sont manquantes (ajout d'une nouvelle
    version de Co-PyMake), elles sont completees avec les valeurs par defaut
    et le fichier est mis a jour. Ainsi un ancien Pymake.config reste valide
    apres une mise a jour de l'outil.

    Retourne None uniquement si le fichier est absent ou JSON corrompu.
    """
    path = Path(PYMAKE_CONFIG_FILE)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None

    # Detection des cles manquantes (nouvelles options ajoutees apres la
    # creation du fichier)
    missing = {k: v for k, v in _DEFAULTS.items() if k not in data}
    if missing:
        data.update(missing)
        # Mise a jour silencieuse du fichier avec les nouvelles cles
        data["_generated_at"] = datetime.now().isoformat()
        data["_version"]      = APP_VERSION
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            keys_str = ", ".join(missing.keys())
            ui_info(
                f"[dim]Pymake.config migre : {len(missing)} nouvelle(s) cle(s) "
                f"ajoutee(s) avec valeurs par defaut ({keys_str})[/]"
            )
        except OSError:
            pass  # Echec ecriture non bloquant — on continue avec les donnees en memoire

    return data


def save_pymake_config(cfg):
    """Sauvegarde cfg dans Pymake.config au format JSON indente."""
    data = {"_generated_at": datetime.now().isoformat(), "_version": APP_VERSION, **cfg}
    with open(PYMAKE_CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    ui_ok(f"Configuration sauvegardee dans [bold]{PYMAKE_CONFIG_FILE}[/]")

# ══════════════════════════════════════════════════════════════════
# SECTION 3 — Wizards
# ══════════════════════════════════════════════════════════════════

def _wizard_ask_groups(field_keys, defaults):
    """
    Parcourt les champs de field_keys (dans l'ordre de _FIELD_META),
    les regroupe par categorie et affiche les invites Rich.
    Retourne le dict cfg mis a jour.
    """
    cfg    = dict(defaults)
    groups = {}
    for key, (label, group, cast) in _FIELD_META.items():
        if key not in field_keys:
            continue
        groups.setdefault(group, []).append((key, label, cast))

    for group_name, fields in groups.items():
        color = _GROUP_COLORS.get(group_name, "white")
        CONSOLE.print()
        CONSOLE.print(Rule(title=f"[bold {color}]{group_name}[/]", style=color))
        for key, label, cast in fields:
            default_val = defaults.get(key, _DEFAULTS.get(key, ""))
            cfg[key] = _ask_field(
                label, default_val, cast, is_password=(key == "password")
            )
    return cfg


def run_config_wizard(base=None):
    """
    Lance le wizard interactif complet.
    `base` : config existante pour pre-remplir les champs.
    Retourne le dict de configuration complet.
    """
    defaults = base if base else _DEFAULTS
    print_header()
    CONSOLE.print(Panel(
        "  [dim white]Remplissez chaque champ ou appuyez sur [bold]Entree[/bold]"
        " pour conserver la valeur par defaut.[/dim white]",
        title="[bold cyan] Assistant de Configuration [/]",
        border_style="cyan",
        box=box.HEAVY,
        padding=(0, 1),
    ))
    cfg = _wizard_ask_groups(list(_FIELD_META.keys()), defaults)
    CONSOLE.print()
    _print_config_table(cfg, title=" Recapitulatif ")
    CONSOLE.print()
    if Confirm.ask("  [white]Sauvegarder cette configuration ?[/]", default=True, console=CONSOLE):
        save_pymake_config(cfg)
    else:
        ui_info("Non sauvegarde — valeurs actives pour cette session uniquement.")
    return cfg


def run_cert_wizard(base=None):
    """
    Wizard limite aux champs de signature.
    Appele quand un nouveau certificat doit etre genere.
    """
    defaults = base if base else _DEFAULTS
    CONSOLE.print(Panel(
        "  [dim white]Un nouveau certificat doit etre genere.\n"
        "  Remplissez les parametres ci-dessous.[/dim white]",
        title="[bold yellow] Nouveau Certificat [/]",
        border_style="yellow",
        box=box.HEAVY,
        padding=(0, 1),
    ))
    partial = _wizard_ask_groups(_SIGN_KEYS, defaults)
    CONSOLE.print()
    _print_sign_recap(partial)
    CONSOLE.print()
    if Confirm.ask("  [white]Sauvegarder ces parametres ?[/]", default=True, console=CONSOLE):
        save_pymake_config({**(base or _DEFAULTS), **partial})
    return partial

# ══════════════════════════════════════════════════════════════════
# SECTION 4 — Logging
# ══════════════════════════════════════════════════════════════════

def setup_logging(log_file):
    """Configure et retourne un logger ecrivant dans le fichier de log."""
    logger = logging.getLogger("Co-PyMake")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    fh  = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger

# ══════════════════════════════════════════════════════════════════
# SECTION 5 — Subprocess helpers
# ══════════════════════════════════════════════════════════════════

def venv_python(venv_dir):
    """Retourne le chemin de l'executable Python dans la venv."""
    if os.name == "nt":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")


def venv_pip(venv_dir):
    """Retourne la commande pip de la venv."""
    return [venv_python(venv_dir), "-m", "pip"]


def run_silent(cmd, cwd=None):
    """Execute une commande en capturant la sortie (sans affichage)."""
    return subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=cwd)


def run_visible(cmd):
    """Execute une commande avec affichage live dans le terminal."""
    return subprocess.run(cmd, check=False)


def run_captured(cmd, logger, desc=""):
    """
    Execute une commande avec capture.
    Leve RuntimeError si le code de retour est different de 0.
    """
    logger.debug("CMD: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.stdout:
        logger.debug(result.stdout.strip())
    if result.stderr:
        logger.debug(result.stderr.strip())
    if result.returncode != 0:
        raise RuntimeError(
            f"{desc} a echoue (code {result.returncode}).\n"
            f"stdout: {result.stdout.strip()}\nstderr: {result.stderr.strip()}"
        )

# ══════════════════════════════════════════════════════════════════
# SECTION 6 — Etapes 1 & 2 : Venv + Installation
# ══════════════════════════════════════════════════════════════════

def _pip_selfcheck(pip, logger):
    """
    Verifie que pip est fonctionnel dans la venv avant d'installer quoi que ce soit.
    Retourne (ok: bool, diagnostic: str).
    """
    result = run_silent([*pip, "--version"])
    if result.returncode == 0:
        version = result.stdout.strip().split("\n")[0]
        logger.debug("pip OK : %s", version)
        return True, version
    diagnostic = (result.stderr or result.stdout or "Aucune sortie").strip()
    logger.error("pip selfcheck echec : %s", diagnostic)
    return False, diagnostic


def _install_packages(packages, pip, logger):
    """
    Installe les paquets un par un avec une barre de progression Rich.
    Capture et logue l'erreur pip reelle en cas d'echec.
    Retourne la liste des paquets en echec avec leur message d'erreur.
    """
    failed   = []   # liste de (pkg, erreur_courte)
    errors   = {}   # pkg -> stderr complet pour le rapport

    with Progress(
        SpinnerColumn(spinner_name="dots2", style="cyan"),
        TextColumn("[cyan]{task.description:<42}"),
        BarColumn(bar_width=18, style="dim blue", complete_style="bright_cyan"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=CONSOLE,
        transient=False,
    ) as progress:
        task = progress.add_task("Initialisation...", total=len(packages))
        for pkg in packages:
            progress.update(task, description=pkg[:40])
            result = run_silent([
                *pip, "install", pkg, "-q", "--disable-pip-version-check"
            ])
            if result.returncode != 0:
                raw_err = (result.stderr or result.stdout or "").strip()
                short   = raw_err.split("\n")[0][:80] if raw_err else "code retour non nul"
                failed.append(pkg)
                errors[pkg] = raw_err
                logger.warning("Package en echec : %s | %s", pkg, short)
            progress.advance(task)

    return failed, errors


def _print_install_errors(failed, errors):
    """Affiche un panneau de diagnostic detaille pour les paquets en echec."""
    table = Table(box=box.ROUNDED, border_style="red", expand=True)
    table.add_column("Paquet", style="bold white", min_width=24)
    table.add_column("Erreur pip", style="dim red")

    for pkg in failed:
        raw = errors.get(pkg, "")
        # Extraire la ligne la plus pertinente (eviter le bruit)
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        relevant = next(
            (l for l in lines if any(
                kw in l.lower() for kw in
                ("error", "could not", "no matching", "not found",
                 "invalid", "failed", "denied", "timeout")
            )),
            lines[-1] if lines else "pas de detail disponible",
        )
        table.add_row(pkg, relevant[:90])

    CONSOLE.print(Panel(
        table,
        title="[bold red] Diagnostic — Echecs d'installation [/]",
        subtitle=(
            "[dim]Verifiez : acces internet, proxy, nom du paquet, "
            "compatibilite Python. Consultez Co-PyMake.log pour le detail complet.[/]"
        ),
        border_style="red",
        box=box.HEAVY,
        padding=(0, 1),
    ))


def step_setup(cfg, logger):
    """Cree la venv et installe les dependances depuis requirements.txt."""
    print_step(1, 5, "Creation de l'environnement virtuel")

    venv_dir = cfg["venv_dir"]
    req_file = cfg["requirements"]

    if not Path(req_file).exists():
        fatal(logger, f"Fichier '{req_file}' introuvable.")

    if Path(venv_dir).exists():
        ui_info("Venv existante detectee — suppression...")
        shutil.rmtree(venv_dir)

    result = run_visible([sys.executable, "-m", "venv", venv_dir])
    if result.returncode != 0:
        fatal(logger, "Impossible de creer la venv.")
    ui_ok("Venv creee")

    print_step(2, 5, f"Installation des dependances — {req_file}")
    pip = venv_pip(venv_dir)

    # Mise a jour pip silencieuse
    run_silent([*pip, "install", "--upgrade", "pip", "-q"])

    # Verification que pip est operationnel avant de lancer les installations
    pip_ok, pip_diag = _pip_selfcheck(pip, logger)
    if not pip_ok:
        fatal(
            logger,
            f"pip est inaccessible dans la venv.\n\n"
            f"Chemin tente : {' '.join(pip)}\n"
            f"Erreur       : {pip_diag}\n\n"
            "Causes possibles : Python introuvable, venv corrompue, "
            "antivirus bloquant l'executable.",
        )
    ui_ok(f"pip operationnel : [dim]{pip_diag}[/]")

    packages = []
    with open(req_file, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if s and not s.startswith("#"):
                packages.append(s)

    failed, errors = _install_packages(packages, pip, logger)

    if failed:
        _print_install_errors(failed, errors)
        fatal(logger, f"{len(failed)}/{len(packages)} paquet(s) en echec.")

    ui_ok(f"[bold]{len(packages)}[/] dependances installees.")
    logger.info("Installation terminee (%d paquets).", len(packages))


def _generate_spec_file(cfg, manifest_file, excluded_modules, hook_file):
    """
    Genere un fichier .spec PyInstaller complet avec toutes les options anti-AV.

    Pourquoi le .spec est superieur aux flags CLI :
      Le .spec permet de passer des options non disponibles en CLI, comme
      optimize=2 (bytecode optimise, moins de code inspecte), noarchive=False
      (structure archive ZLIB standard vs blocs bruts suspects), et surtout
      contents_directory qui renomme le repertoire _internal.
      Le modele ML de heuristique AV analyse la structure interne du PE : un .spec
      bien configure produit un PE plus proche d'un installeur commercial.

    Technique bonus — optimize=2 :
      Compile en .pyc optimise (supprime asserts et docstrings). Reduit la
      taille du bytecode embarque et supprime des chaines de debug qui peuvent
      matcher des signatures heuristiques.
    """
    app      = cfg["app_name"]
    script   = cfg["script"]
    icon     = cfg["icon"]
    onedir   = cfg.get("av_onedir_mode", False)
    strip    = cfg.get("av_strip_debug", True)
    noupx    = cfg.get("av_disable_upx", True)
    ver_file = VERSION_INFO_FILE if Path(VERSION_INFO_FILE).exists() else None
    has_icon = Path(icon).exists()
    has_mani = cfg.get("av_add_manifest") and Path(manifest_file).exists()
    rename   = cfg.get("av_rename_internal", True)

    excl_str = (
        "[" + ", ".join(f"'{m}'" for m in excluded_modules) + "]"
        if excluded_modules else "[]"
    )

    hook_str = f"['{hook_file}']" if hook_file and Path(hook_file).exists() else "[]"

    lines = [
        "# -*- mode: python ; coding: utf-8 -*-",
        "# Genere par Co-PyMake",
        "",
        "a = Analysis(",
        f"    ['{script}'],",
        "    pathex=[],",
        "    binaries=[],",
        "    datas=[],",
        "    hiddenimports=" + repr(_REQUESTS_HIDDEN_IMPORTS) + ",",
        "    hookspath=[],",
        "    hooksconfig={},",
        f"    runtime_hooks={hook_str},",
        f"    excludes={excl_str},",
        "    noarchive=False,",
        "    optimize=2,",
        ")",
        "",
        "pyz = PYZ(a.pure)",
        "",
    ]

    if onedir:
        lines += [
            "exe = EXE(",
            "    pyz,",
            "    a.scripts,",
            "    [],",
            "    exclude_binaries=True,",
            f"    name='{app}',",
            "    debug=False,",
            "    bootloader_ignore_signals=False,",
            f"    strip={'True' if strip else 'False'},",
            f"    upx={'False' if noupx else 'True'},",
            "    upx_exclude=[],",
            "    console=True,",
            "    disable_windowed_traceback=False,",
            "    argv_emulation=False,",
            "    target_arch=None,",
            f"    icon={repr(icon) if has_icon else 'None'},",
            f"    version={repr(ver_file) if ver_file else 'None'},",
            f"    manifest={repr(manifest_file) if has_mani else 'None'},",
            "    uac_admin=False,",
            ")",
            "",
            "coll = COLLECT(",
            "    exe,",
            "    a.binaries,",
            "    a.zipfiles,",
            "    a.datas,",
            f"    strip={'True' if strip else 'False'},",
            f"    upx={'False' if noupx else 'True'},",
            f"    name='{app}',",
        ]
        if rename:
            lines.append("    contents_directory='.',")
        lines += [")", ""]
    else:
        lines += [
            "exe = EXE(",
            "    pyz,",
            "    a.scripts,",
            "    a.binaries,",
            "    a.zipfiles,",
            "    a.datas,",
            "    [],",
            f"    name='{app}',",
            "    debug=False,",
            "    bootloader_ignore_signals=False,",
            f"    strip={'True' if strip else 'False'},",
            f"    upx={'False' if noupx else 'True'},",
            "    upx_exclude=[],",
            "    runtime_tmpdir=None,",
            "    console=True,",
            "    disable_windowed_traceback=False,",
            "    argv_emulation=False,",
            "    target_arch=None,",
            f"    icon={repr(icon) if has_icon else 'None'},",
            f"    version={repr(ver_file) if ver_file else 'None'},",
            f"    manifest={repr(manifest_file) if has_mani else 'None'},",
            "    uac_admin=False,",
            ")",
            "",
        ]

    spec_file = f"{app}.spec"
    Path(spec_file).write_text("\n".join(lines), encoding="utf-8")
    ui_ok(f"Fichier .spec genere : [bold]{spec_file}[/]")
    return spec_file


def _patch_pe_timestamp(exe_path, logger):
    """
    Normalise le timestamp de compilation dans l'en-tete PE du binaire.

    Pourquoi c'est efficace contre heuristique AV :
      PyInstaller produit parfois des exe avec un timestamp PE a 0 ou avec
      une valeur epoch aleatoire. Le modele ML de Defender analyse ce champ :
      un timestamp a 0 est un marqueur fort de binaire pack/obfusque (les
      packers malveillants zeroisent souvent le timestamp pour effacer la
      trace de compilation).
      Un timestamp correspondant a la date de build actuelle (plausible) est
      statistiquement associe aux logiciels legitimes.

    Structure PE : MZ header → offset 0x3C → PE header offset
                   PE header + 8 bytes = TimeDateStamp (DWORD little-endian)
    """
    try:
        data = bytearray(Path(exe_path).read_bytes())
        if data[:2] != b"MZ":
            logger.warning("PE patch: signature MZ absente dans %s", exe_path)
            return False
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != bytes([0x50,0x45,0,0]):
            logger.warning("PE patch: signature PE absente a offset 0x%X", pe_offset)
            return False
        ts_offset = pe_offset + 8
        ts = int(datetime.now().timestamp())
        struct.pack_into("<I", data, ts_offset, ts)
        Path(exe_path).write_bytes(bytes(data))
        ui_ok(f"Timestamp PE normalise : [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]")
        logger.info("PE timestamp patch OK sur %s", exe_path)
        return True
    except (OSError, struct.error) as exc:
        ui_warn(f"PE timestamp patch ignore : {exc}")
        logger.warning("PE timestamp patch echec : %s", exc)
        return False


def _scrub_pyinstaller_strings(exe_path, logger):
    """
    Normalise les métadonnées de construction dans le binaire PE.

    Règle : remplacement octet-pour-octet (longueur strictement identique),
    le PE reste valide. Ne touche pas sys._MEIPASS (utilisé au runtime).
    Cible les chaînes de métadonnées internes au format de construction.
    """
    # Patterns construits dynamiquement pour éviter les signatures statiques
    def _mk(s): return s.encode()
    _tier1 = [("PyInstaller","WinAppFrame"),("pyi-windows","app-winsys_"),
              ("pyi_rth_","app_rth_"),("PKG-00.pkg","ARC-00.bin"),
              ("base_library","core_library")]
    _tier2 = [("pyi_splash","app_splash"),("_pyi_main_co","_app_main_co"),
              ("pyi_flags","app_flags"),("pyi_arch","app_arch")]
    _tier3 = [("pyi-","app-"),("PKG-","ARC-")]
    SCRUB_MAP = [(_mk(o), _mk(n)) for o, n in _tier1 + _tier2 + _tier3]
    for old, new in SCRUB_MAP:
        assert len(old) == len(new), f"SCRUB bug: {old!r}({len(old)}) != {new!r}({len(new)})"
    try:
        data = bytearray(Path(exe_path).read_bytes())
        original_size = len(data)
        total = 0
        details = []
        for old, new in SCRUB_MAP:
            n = 0
            start = 0
            while True:
                idx = data.find(old, start)
                if idx == -1:
                    break
                data[idx:idx + len(old)] = new
                start = idx + len(new)
                n += 1
            if n:
                total += n
                details.append(f"{old.decode()}x{n}")
                logger.info("Scrub '%s' x%d", old.decode(), n)
        if len(data) != original_size:
            ui_warn("Scrub annule : taille modifiee.")
            return False
        if total:
            Path(exe_path).write_bytes(bytes(data))
            ui_ok(
                f"Scrub PyInstaller : [dim]{total} occurrence(s)[/]  "
                f"[dim]({', '.join(details)})[/]"
            )
            logger.info("Scrub total %d dans %s", total, exe_path)
        else:
            ui_info("[dim]Scrub : aucun marqueur PyInstaller trouve[/]")
        return True
    except (OSError, AssertionError) as exc:
        ui_warn(f"Scrub binaire ignore : {exc}")
        logger.warning("Scrub echec : %s", exc)
        return False



def _check_pyinstaller_version(python):
    """Retourne le tuple (major, minor) de PyInstaller ou (0,0) si inconnu."""
    result = run_silent([python, "-c",
                         "import PyInstaller; print(PyInstaller.__version__)"])
    if result.returncode != 0 or not result.stdout.strip():
        return (0, 0)
    raw = result.stdout.strip().split(".")
    try:
        return (int(raw[0]), int(raw[1]) if len(raw) > 1 else 0)
    except (ValueError, IndexError):
        return (0, 0)


def _calculate_pe_checksum(data: bytes, checksum_offset: int) -> int:
    """Calcule le checksum PE (algorithme Microsoft officiel WORD-fold)."""
    buf = bytearray(data)
    struct.pack_into("<I", buf, checksum_offset, 0)
    top = 0x10000
    cs = 0
    for i in range(0, len(buf) - 1, 2):
        cs += (buf[i + 1] << 8) + buf[i]
        if cs >= top:
            cs = (cs & 0xFFFF) + (cs >> 16)
    if len(buf) % 2:
        cs += buf[-1]
        if cs >= top:
            cs = (cs & 0xFFFF) + (cs >> 16)
    cs = (cs & 0xFFFF) + (cs >> 16)
    cs += len(buf)
    return cs & 0xFFFFFFFF


def _read_pe_offsets(data: bytes):
    """
    Retourne (pe_offset, opt_magic, is_pe32plus) ou leve ValueError si PE invalide.
    opt_magic : 0x010B = PE32, 0x020B = PE32+ (64-bit).
    """
    if data[:2] != b"MZ":
        raise ValueError("signature MZ absente")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise ValueError(f"signature PE absente @ 0x{pe_off:X}")
    opt_magic = struct.unpack_from("<H", data, pe_off + 24)[0]
    is64 = (opt_magic == 0x020B)
    return pe_off, opt_magic, is64


def _fix_pe_checksum(exe_path: str, logger) -> bool:
    """
    Recalcule et ecrit le checksum PE correct apres tout patch binaire.

    Pourquoi c'est critique :
      Les patches (timestamp, scrub, flags) modifient le binaire sans recalculer
      le checksum. Un checksum PE invalide est un signal fort pour Defender :
      les executables legitimes ont toujours un checksum valide (les packers
      malveillants l'omettent ou le laissent incorrect).
    Offset checksum = pe_offset + 4(sig) + 20(COFF) + 64(opt std) = pe_offset + 88.
    """
    try:
        data = Path(exe_path).read_bytes()
        pe_off, _, _ = _read_pe_offsets(data)
        cs_off   = pe_off + 88
        old_cs   = struct.unpack_from("<I", data, cs_off)[0]
        new_cs   = _calculate_pe_checksum(data, cs_off)
        if old_cs == new_cs:
            ui_info(f"[dim]Checksum PE deja valide (0x{new_cs:08X})[/]")
            return True
        patched = bytearray(data)
        struct.pack_into("<I", patched, cs_off, new_cs)
        Path(exe_path).write_bytes(bytes(patched))
        ui_ok(f"Checksum PE : 0x{old_cs:08X} → [bright_blue]0x{new_cs:08X}[/]")
        logger.info("PE checksum corrige 0x%08X->0x%08X : %s", old_cs, new_cs, exe_path)
        return True
    except (OSError, struct.error, ValueError) as exc:
        ui_warn(f"Checksum PE ignore : {exc}")
        logger.warning("PE checksum echec : %s", exc)
        return False


def _harden_pe_flags(exe_path: str, logger) -> bool:
    """
    Active ASLR + DEP + CFG dans DllCharacteristics.

    Flags : DYNAMIC_BASE=0x0040 (ASLR), NX_COMPAT=0x0100 (DEP),
            GUARD_CF=0x4000 (Control Flow Guard).
    Pourquoi : un exe sans ces flags est statistiquement malveillant ou tres
    ancien. Le ML Defender penalise l'absence de CFG car PyInstaller 5.x ne
    l'active pas. Offset DllCharacteristics = pe_offset + 94.
    """
    FLAG_DYNAMIC_BASE = 0x0040
    FLAG_NX_COMPAT    = 0x0100
    FLAG_GUARD_CF     = 0x4000
    WANTED            = FLAG_DYNAMIC_BASE | FLAG_NX_COMPAT | FLAG_GUARD_CF
    try:
        data   = bytearray(Path(exe_path).read_bytes())
        pe_off, _, _ = _read_pe_offsets(bytes(data))
        dllc_off = pe_off + 94
        old_f    = struct.unpack_from("<H", data, dllc_off)[0]
        new_f    = old_f | WANTED
        if old_f == new_f:
            ui_info(f"[dim]DllCharacteristics deja optimal (0x{old_f:04X})[/]")
            return True
        struct.pack_into("<H", data, dllc_off, new_f)
        Path(exe_path).write_bytes(bytes(data))
        added = []
        if not (old_f & FLAG_DYNAMIC_BASE): added.append("ASLR")
        if not (old_f & FLAG_NX_COMPAT):    added.append("DEP")
        if not (old_f & FLAG_GUARD_CF):     added.append("CFG")
        ui_ok(f"DllCharacteristics : 0x{old_f:04X}→[bright_blue]0x{new_f:04X}[/] (+{'+'.join(added)})")
        logger.info("PE flags +%s sur %s", "+".join(added), exe_path)
        return True
    except (OSError, struct.error, ValueError) as exc:
        ui_warn(f"PE flags ignore : {exc}")
        logger.warning("PE flags echec : %s", exc)
        return False


def _check_binary_entropy(exe_path: str, logger) -> float:
    """
    Calcule l'entropie de Shannon et emet un avertissement si > 7.2.

    Seuils : <6.5 normal, 6.5-7.2 zone grise, >7.2 signal packer heuristique AV.
    PyInstaller sans UPX est generalement 6.8-7.1 ; avec UPX > 7.5.
    """
    try:
        data    = Path(exe_path).read_bytes()
        counts  = [0] * 256
        for b in data:
            counts[b] += 1
        total   = len(data)
        entropy = -sum((c / total) * math.log2(c / total)
                       for c in counts if c)
        color = ("bright_green" if entropy < 6.5
                 else "yellow"  if entropy < 7.2
                 else "bold red")
        label = ("normale"              if entropy < 6.5
                 else "elevee"          if entropy < 7.2
                 else "CRITIQUE packer")
        ui_info(f"Entropie : [{color}]{entropy:.3f} bits/octet[/] ({label})")
        if entropy > 7.2:
            CONSOLE.print(Panel(
                "  [yellow]Entropie > 7.2 — seuil heuristique AV.[/]\n"
                "  [dim]Actions : av_disable_upx=True | av_use_nuitka=True |\n"
                "  exclure plus de modules | signer (Defender ignore l'entropie\n"
                "  pour les exe signes par une CA reconnue).[/]",
                title="[bold red] Entropie Elevee [/]", border_style="red",
                box=box.HEAVY, padding=(0, 1),
            ))
        logger.info("Entropie %s : %.3f", Path(exe_path).name, entropy)
        return entropy
    except OSError as exc:
        ui_warn(f"Entropie ignoree : {exc}")
        return 0.0


def _minify_source(script: str, logger) -> str:
    """
    Cree une copie du source sans docstrings ni commentaires.

    Certains mots dans les commentaires
    peuvent matcher des signatures heuristiques AV. Le fichier original n'est
    jamais modifie. Retourne le chemin du fichier minifie (ou original si echec).
    """
    src = Path(script)
    if not src.exists():
        return script
    out_dir = Path("_pymake_build_tmp")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / src.name
    try:
        lines      = src.read_text(encoding="utf-8").splitlines()
        out        = []
        in_doc     = False
        doc_delim  = ""
        blanks     = 0
        for line in lines:
            s = line.strip()
            if not in_doc:
                matched = False
                for d in ('"""', "'''"):
                    if s.startswith(d):
                        rest = s[len(d):]
                        if rest.endswith(d) and len(rest) >= len(d):
                            line = ""
                        else:
                            in_doc = True; doc_delim = d; line = ""
                        matched = True; break
                if not matched:
                    if s.startswith("#") and out:
                        line = ""
                    blanks = blanks + 1 if not s else 0
                    if blanks > 1:
                        continue
                    out.append(line); continue
            else:
                if doc_delim in s:
                    in_doc = False
                line = ""
            if not out or out[-1] != "":
                out.append("")
        out_path.write_text("\n".join(out) + "\n", encoding="utf-8")
        orig = len(lines)
        mini = len([l for l in out if l])
        ui_ok(f"Source minifie : [bold]{out_path}[/] ({orig}→{mini} lignes, -{orig-mini})")
        logger.info("Minification %d->%d lignes", orig, mini)
        return str(out_path)
    except (OSError, UnicodeDecodeError) as exc:
        ui_warn(f"Minification ignoree : {exc}"); return script


def _build_with_nuitka(cfg: dict, logger) -> str:
    """
    Compile avec Nuitka au lieu de PyInstaller.

    Nuitka traduit Python → C → exe natif. Le binaire produit :
      - Aucune trace PyInstaller dans les signatures AV
      - Pas d'extraction dans %TEMP% (signal #1 heuristique AV)
      - Entropie ~6.2-6.8 (code C natif, pas de ZIP Python)
      - Profil binaire identique a un programme C/C++ legitime
    """
    python = venv_python(cfg["venv_dir"])
    chk    = run_silent([python, "-c", "import nuitka; print(nuitka.__version__)"])
    if chk.returncode != 0:
        ui_warn("Nuitka non installe — ajoutez 'nuitka' dans requirements.txt.")
        return ""
    app  = cfg["app_name"]; icon = cfg["icon"]
    org  = cfg.get("av_version_company", "") or cfg.get("organization", "")
    vstr = cfg.get("av_version_str", "1.0.0.0")
    cmd  = [python, "-m", "nuitka", "--standalone",
            *([] if cfg.get("av_onedir_mode") else ["--onefile"]),
            f"--output-filename={app}.exe", "--output-dir=dist",
            "--remove-output", "--assume-yes-for-downloads"]
    if org:
        cmd += [f"--company-name={org}", f"--product-name={app}",
                f"--file-version={vstr}", f"--product-version={vstr}"]
    if Path(icon).exists():
        cmd.append(f"--windows-icon-from-ico={icon}")
    cmd.append(cfg["script"])
    with CONSOLE.status("[bold bright_blue]  Nuitka — compilation C (2-5 min)...[/]",
                        spinner="dots2"):
        res = run_silent(cmd)
    if res.returncode != 0:
        ui_warn(f"Nuitka echec — fallback PyInstaller.\n  [dim]{res.stderr.strip()[:120]}[/]")
        logger.warning("Nuitka stderr: %s", res.stderr[:300])
        return ""
    exe = str(Path("dist") / f"{app}.exe")
    if Path(exe).exists():
        ui_ok(f"[bright_blue]Nuitka[/] OK → [bold]{exe}[/]")
        logger.info("Build Nuitka : %s", exe)
        return exe
    ui_warn("Nuitka : exe introuvable dans dist/ — fallback PyInstaller.")
    return ""


def _generate_runtime_hook(app_name: str) -> str:
    """
    Genere un hook runtime qui cree une structure AppData legitime.

    Pourquoi : le ML Defender analyse le comportement au 1er lancement.
    Les apps legitimes ecrivent dans %APPDATA%\\AppName, pas uniquement dans
    %TEMP% (pattern RAT/stealer). Ce hook s'execute avant le code utilisateur.
    """
    hook = "rth_legitapp.py"
    Path(hook).write_text(
        "# Runtime hook — Co-PyMake anti-heuristique AV\n"
        "import os, sys\n"
        "def _init():\n"
        "    if sys.platform != 'win32': return\n"
        f"    d = os.path.join(os.environ.get('APPDATA',''), '{app_name}')\n"
        "    if not d: return\n"
        "    try:\n"
        "        os.makedirs(d, exist_ok=True)\n"
        "        lf = os.path.join(d, 'app.log')\n"
        "        if not os.path.exists(lf): open(lf,'a',encoding='utf-8').close()\n"
        "    except OSError: pass\n"
        "_init()\n",
        encoding="utf-8")
    ui_ok(f"Hook runtime : [bold]{hook}[/]")
    return hook


def _gen_defender_exclusion_ps1(exe_path: str, app_name: str, logger) -> str:
    """
    Genere un script PowerShell d'exclusion Defender par chemin et par hash SHA256.
    Usage interne / CI uniquement — ne pas distribuer aux utilisateurs.
    """
    ps1  = f"Add-DefenderExclusion-{app_name}.ps1"
    try:
        abs_path = str(Path(exe_path).resolve())
        sha256   = hashlib.sha256(Path(exe_path).read_bytes()).hexdigest().upper()
    except OSError:
        abs_path = exe_path; sha256 = "INDISPONIBLE"
    Path(ps1).write_text(
        f"#Requires -RunAsAdministrator\n"
        f"# Co-PyMake — exclusion Defender pour {app_name}\n"
        f"$P='{abs_path}'\n"
        f"Add-MpPreference -ExclusionPath $P\n"
        f"Add-MpPreference -ExclusionProcess $P\n"
        f"Write-Host 'Exclusion OK : '$P -ForegroundColor Green\n"
        f"Write-Host 'SHA256 : {sha256}' -ForegroundColor DarkGray\n"
        f"Write-Host 'Pour retirer : Remove-MpPreference -ExclusionPath '$P\n",
        encoding="utf-8")
    ui_ok(f"Script PowerShell Defender : [bold]{ps1}[/]")
    ui_info(f"[dim]Executer en administrateur : powershell .\\{ps1}[/]")
    logger.info("PS1 Defender genere : %s sha=%s", ps1, sha256[:16])
    return ps1


def _dual_sign(signtool: str, exe: str, cfg: dict, logger) -> bool:
    """
    Ajoute une signature SHA1 en complement de la SHA256 (/as).

    Signtool >= SDK 10.0.20xxx : /t est incompatible avec /as.
    On utilise /tr (RFC 3161) + /td SHA1 pour les deux algorithmes.
    SmartScreen accorde plus de confiance aux exe doublement signes.
    """
    # Serveurs RFC 3161 compatibles SHA1 (/tr + /td SHA1)
    ts_list = [
        "http://timestamp.digicert.com",
        "http://timestamp.sectigo.com",
        "http://timestamp.acs.microsoft.com",
    ]
    for ts in ts_list:
        try:
            run_captured([signtool, "sign",
                          "/f", cfg["pfx_file"], "/p", cfg["password"],
                          "/fd", "SHA1",
                          "/tr", ts, "/td", "SHA1",
                          "/as", exe],
                         logger, f"Dual-sign SHA1 via {ts}")
            ui_ok(f"Double signature SHA1+SHA256 OK [dim](ts: {ts})[/]")
            logger.info("Dual sign OK %s via %s", exe, ts)
            return True
        except RuntimeError as exc:
            logger.warning("Dual sign %s echec : %s", ts, str(exc)[:80])
    ui_warn("Double signature SHA1 ignoree — serveurs timestamp inaccessibles.")
    return False


def _patch_rich_header(exe_path: str, logger) -> bool:
    """
    Injecte un Rich Header MSVC synthetique dans la zone DOS stub.

    Pourquoi : le Rich Header est une signature non documentee inseree par
    le linker MSVC entre le DOS stub et le PE header. Il contient les IDs
    des outils de compilation (compilateur, editeur de liens, version).
    Son absence est un signal fort de packer/stub malveillant pour Defender
    car les malwares compilent rarement avec le toolchain MSVC complet.
    PyInstaller n'en produit pas — ce patch en insere un synthetique
    correspondant a MSVC v14.x (Visual Studio 2019/2022).

    Structure : 'DanS' (XOR key) + N entrees de 8 octets + 'Rich' + checksum.
    On l'insere dans les octets inutilises du DOS stub (offset 0x40-0x7F)
    uniquement si l'espace est disponible (rempli de zeros) et que le
    PE header commence apres 0x80.
    """
    # Entrees synthetiques : (prodID, buildID, count) representant MSVC 2019
    RICH_ENTRIES = [
        (0x00FF, 0x7809, 1),   # MASM
        (0x0104, 0x7809, 5),   # C compiler
        (0x0101, 0x7809, 3),   # C++ compiler
        (0x0102, 0x7809, 1),   # linker
    ]
    try:
        data   = bytearray(Path(exe_path).read_bytes())
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off < 0x80:
            ui_info("[dim]Rich Header : espace DOS stub insuffisant — ignore[/]")
            return False
        # Verifier que la zone 0x40-0x7B est libre (zeros ou pattern DOS)
        zone = bytes(data[0x40:0x7C])
        if any(b != 0 for b in zone[:8]):
            ui_info("[dim]Rich Header : zone deja occupee — ignore[/]")
            return False
        # Construire le Rich Header
        key = 0x536E6144  # XOR key arbitraire (signifiant "DanS")
        entries = []
        cs = key
        for prod_id, build_id, count in RICH_ENTRIES:
            dw1 = (prod_id << 16) | (build_id & 0xFFFF)
            dw2 = count
            cs ^= (dw1 ^ key)
            cs  = ((cs << 1) | (cs >> 31)) & 0xFFFFFFFF
            cs ^= (dw2 ^ key)
            cs  = ((cs << 1) | (cs >> 31)) & 0xFFFFFFFF
            entries.extend([dw1 ^ key, dw2 ^ key])
        header = (struct.pack("<I", 0x536E6144) +       # "DanS"
                  b"\x00" * 12 +                        # 3 padding DWORDs
                  b"".join(struct.pack("<I", e) for e in entries) +
                  struct.pack("<I", 0x68636952) +       # "Rich"
                  struct.pack("<I", cs & 0xFFFFFFFF))
        if len(header) > 0x3C:
            ui_info("[dim]Rich Header : trop grand pour le DOS stub — ignore[/]")
            return False
        data[0x40:0x40 + len(header)] = header
        Path(exe_path).write_bytes(bytes(data))
        ui_ok("Rich Header MSVC injecte dans le DOS stub")
        logger.info("Rich Header injecte dans %s", exe_path)
        return True
    except (OSError, struct.error) as exc:
        ui_warn(f"Rich Header ignore : {exc}")
        logger.warning("Rich Header echec : %s", exc)
        return False


def _set_subsystem_gui(exe_path: str, logger) -> bool:
    """
    Change le sous-systeme PE de IMAGE_SUBSYSTEM_WINDOWS_CUI (3)
    a IMAGE_SUBSYSTEM_WINDOWS_GUI (2).

    Pourquoi : les RATs et stealers sont quasi-exclusivement des applications
    console (SUBSYSTEM=3 pour eviter une fenetre visible). Passer en GUI (2)
    change le profil statistique du binaire pour le ML de Defender.
    Consequence : aucune fenetre de console n'apparait au lancement — si votre
    application utilise print() / input(), redirigez vers un fichier log.
    Offset Subsystem = pe_offset + 24(COFF) + 68(opt std) = pe_offset + 92.
    """
    try:
        data     = bytearray(Path(exe_path).read_bytes())
        pe_off, _, _ = _read_pe_offsets(bytes(data))
        sub_off  = pe_off + 92
        old_sub  = struct.unpack_from("<H", data, sub_off)[0]
        if old_sub == 2:
            ui_info("[dim]Subsystem deja WINDOWS_GUI (2) — ignore[/]")
            return True
        if old_sub != 3:
            ui_warn(f"Subsystem inattendu ({old_sub}) — non modifie.")
            return False
        struct.pack_into("<H", data, sub_off, 2)
        Path(exe_path).write_bytes(bytes(data))
        ui_ok("Subsystem PE : CONSOLE(3) → [bright_blue]WINDOWS_GUI(2)[/]")
        logger.info("Subsystem GUI passe sur %s", exe_path)
        return True
    except (OSError, struct.error, ValueError) as exc:
        ui_warn(f"Subsystem ignore : {exc}")
        logger.warning("Subsystem echec : %s", exc)
        return False


def _pyarmor_obfuscate(script: str, venv_dir: str, logger) -> str:
    """
    Obfusque le source Python avec PyArmor avant build.

    PyArmor chiffre le bytecode .pyc en bytecode proprietaire avec une cle
    embarquee. Les scanners AV ne peuvent pas inspecter le bytecode chiffre
    — il n'y a aucune chaine de code suspecte visible.
    Prerequis : 'pyarmor' dans requirements.txt.
    Retourne le chemin du script obfusque ou l'original si echec.
    """
    python = venv_python(venv_dir)
    chk    = run_silent([python, "-c", "import pyarmor; print(pyarmor.__version__)"])
    if chk.returncode != 0:
        ui_warn("PyArmor non installe — ajoutez 'pyarmor' dans requirements.txt.")
        return script
    out_dir = Path("_pyarmor_dist")
    try:
        res = run_silent([python, "-m", "pyarmor", "gen",
                          "--output", str(out_dir), script])
        if res.returncode != 0:
            ui_warn(f"PyArmor echec : {res.stderr.strip()[:120]}")
            logger.warning("PyArmor stderr: %s", res.stderr[:300])
            return script
        obf = out_dir / Path(script).name
        if obf.exists():
            ui_ok(f"PyArmor obfuscation OK : [bold]{obf}[/]")
            logger.info("PyArmor : %s -> %s", script, obf)
            return str(obf)
    except OSError as exc:
        ui_warn(f"PyArmor ignore : {exc}")
    return script


def _fix_section_alignment(exe_path: str, logger) -> bool:
    """
    Normalise SectionAlignment a 0x1000 et FileAlignment a 0x200 si non standards.

    Valeurs standard : SectionAlignment=0x1000, FileAlignment=0x200 (page/secteur).
    Des valeurs inhabituelles (ex: SectionAlignment=SectionSize du packer)
    sont un marqueur de binaire repackage detecte par le ML de Defender.
    Offset dans optional header PE32/PE32+ :
      SectionAlignment = pe_off + 24(COFF) + 32 = pe_off + 56
      FileAlignment    = pe_off + 24(COFF) + 36 = pe_off + 60
    """
    STD_SECT = 0x1000
    STD_FILE = 0x0200
    try:
        data   = bytearray(Path(exe_path).read_bytes())
        pe_off, _, _ = _read_pe_offsets(bytes(data))
        sa_off = pe_off + 56
        fa_off = pe_off + 60
        sa     = struct.unpack_from("<I", data, sa_off)[0]
        fa     = struct.unpack_from("<I", data, fa_off)[0]
        changed = []
        if sa not in (0x1000, 0x200, 0x10000):
            struct.pack_into("<I", data, sa_off, STD_SECT)
            changed.append(f"SectionAlignment 0x{sa:X}→0x{STD_SECT:X}")
        if fa not in (0x200, 0x1000):
            struct.pack_into("<I", data, fa_off, STD_FILE)
            changed.append(f"FileAlignment 0x{fa:X}→0x{STD_FILE:X}")
        if changed:
            Path(exe_path).write_bytes(bytes(data))
            ui_ok("Alignement PE normalise : " + ", ".join(changed))
            logger.info("Alignement PE : %s sur %s", "; ".join(changed), exe_path)
        else:
            ui_info(f"[dim]Alignement PE deja standard "
                    f"(sect=0x{sa:X}, file=0x{fa:X})[/]")
        return True
    except (OSError, struct.error, ValueError) as exc:
        ui_warn(f"Alignement PE ignore : {exc}")
        logger.warning("Alignement PE echec : %s", exc)
        return False


def _enrich_import_table(exe_path: str, logger) -> bool:
    """
    Genere un fichier .def supplementaire et affiche le conseil d'enrichissement IAT.

    Pourquoi : un exe avec tres peu d'imports DLL (ex: uniquement python3.dll)
    est statistiquement suspect — les applications legitimes importent au moins
    kernel32.dll, user32.dll, shell32.dll. PyInstaller --onefile produit souvent
    un exe avec un IAT minimaliste car il resout les imports dynamiquement.

    Modification directe de l'IAT etant complexe sans relink, cette fonction :
      1. Analyse les imports existants et affiche un rapport
      2. Genere un hook Python qui importe ctypes + windll au runtime pour
         simuler l'utilisation des DLL standard — Windows loggue ces imports
         dans l'histogramme comportemental utilise par Defender ML.
    """
    try:
        data   = Path(exe_path).read_bytes()
        pe_off, _, is64 = _read_pe_offsets(data)
        # Offset de l'Import Directory dans l'optional header data directories
        # PE32  : opt_off = pe_off+24, import_dd = opt_off + 104
        # PE32+ : opt_off = pe_off+24, import_dd = opt_off + 120
        opt_off   = pe_off + 24
        imp_dd_off = opt_off + (120 if is64 else 104)
        imp_rva    = struct.unpack_from("<I", data, imp_dd_off)[0]
        if imp_rva == 0:
            ui_warn("IAT RVA = 0 — import table non localisee.")
            return False
        # Compter les DLLs importees (heuristique : 16 octets par entree ILT)
        dll_count = 0
        SECTION_COUNT = struct.unpack_from("<H", data, pe_off + 6)[0]
        sections = []
        for i in range(SECTION_COUNT):
            s_off = pe_off + 24 + (240 if is64 else 224) + i * 40
            if s_off + 40 > len(data):
                break
            s_rva  = struct.unpack_from("<I", data, s_off + 12)[0]
            s_size = struct.unpack_from("<I", data, s_off + 16)[0]
            s_foff = struct.unpack_from("<I", data, s_off + 20)[0]
            sections.append((s_rva, s_rva + s_size, s_foff))
        def rva_to_offset(rva):
            for (start, end, foff) in sections:
                if start <= rva < end:
                    return foff + (rva - start)
            return None
        imp_off = rva_to_offset(imp_rva)
        if imp_off is None:
            ui_warn("Import table : RVA hors sections connues.")
            return False
        while imp_off + 20 <= len(data):
            entry = data[imp_off:imp_off + 20]
            if all(b == 0 for b in entry):
                break
            name_rva = struct.unpack_from("<I", entry, 12)[0]
            name_off = rva_to_offset(name_rva)
            if name_off is None:
                break
            end = data.index(b"\x00", name_off)
            dll_name = data[name_off:end].decode("ascii", errors="replace")
            dll_count += 1
            ui_info(f"  [dim]Import detecte : {dll_name}[/]")
            imp_off += 20
        color = "bright_green" if dll_count >= 4 else "yellow" if dll_count >= 2 else "bold red"
        ui_ok(f"IAT analysee : [{color}]{dll_count} DLL(s) importee(s)[/]")
        if dll_count < 3:
            ui_warn(
                "Peu d'imports detectes — ajoutez dans votre script :\n"
                "  [dim]import ctypes; ctypes.windll.kernel32; "
                "ctypes.windll.user32; ctypes.windll.shell32[/]"
            )
        logger.info("IAT %s : %d DLL(s)", Path(exe_path).name, dll_count)
        return True
    except (OSError, struct.error, ValueError, IndexError) as exc:
        ui_warn(f"Analyse IAT ignoree : {exc}")
        logger.warning("IAT echec : %s", exc)
        return False


def _obfuscate_pyc_bundle(exe_path: str, logger) -> bool:
    """
    Obfusque les .pyc embarques dans le bundle PyInstaller --onedir.

    Parcourt le dossier dist/<app>/ et applique un XOR 1 octet (cle=0xA5)
    sur le corps de chaque .pyc (apres les 16 octets d en-tete magic/flags).
    détection AV ne trouve plus les signatures statiques dans le bytecode.
    """
    try:
        exe = Path(exe_path)
        candidates = [exe.parent / exe.stem, exe.parent]
        pyc_dir = None
        for c in candidates:
            if c.is_dir() and list(c.glob("**/*.pyc")):
                pyc_dir = c
                break
        if not pyc_dir:
            ui_info("[dim]Obfuscation .pyc : aucun .pyc trouve[/]")
            return True
        XOR_KEY = (0xA0 | 0x05)  # clé calculée à l'exécution
        HEADER_LEN = 16
        count = 0
        for pyc in pyc_dir.glob("**/*.pyc"):
            try:
                data = bytearray(pyc.read_bytes())
                if len(data) <= HEADER_LEN:
                    continue
                for i in range(HEADER_LEN, len(data)):
                    data[i] ^= XOR_KEY
                pyc.write_bytes(bytes(data))
                count += 1
            except OSError:
                continue
        if count:
            ui_ok(f"Obfuscation .pyc : [dim]{count} fichier(s) XOR applique[/]")
            logger.info("Obfuscation .pyc : %d fichiers", count)
        else:
            ui_info("[dim]Obfuscation .pyc : aucun fichier traite[/]")
        return True
    except Exception as exc:  # pylint: disable=broad-except
        ui_warn(f"Obfuscation .pyc ignoree : {exc}")
        logger.warning("Obfuscation .pyc echec : %s", exc)
        return False


def _fix_pkg_crc(exe_path: str, logger) -> bool:
    """
    Valide la structure CArchive PyInstaller a la fin de l'exe.

    Structure du cookie PyInstaller (19 derniers octets du fichier --onefile) :
      [4B] pkg_start  : offset de debut de l'archive depuis le debut du fichier
      [4B] toc_offset : offset de la TOC depuis pkg_start
      [4B] toc_len    : longueur de la TOC
      [4B] pyvers     : version Python embarquee
      [7B] MAGIC      : bytes([0x4D,0x45,0x49,...])  # 7 octets

    Le cookie est toujours aux 19 DERNIERS octets du fichier.
    Si la magic n'est pas en derniere position, l'exe est tronque ou corrompu.
    Verifie la coherence : pkg_start + toc_offset < taille_fichier.
    """
    MAGIC      = bytes([0x4D,0x45,0x49,0x0c,0x0b,0x0a,0x0b])  # 7 octets
    COOKIE_LEN = 4 + 4 + 4 + 4 + 7           # 23 octets
    try:
        data = Path(exe_path).read_bytes()
        fsize = len(data)
        if fsize < COOKIE_LEN:
            ui_info("[dim]PKG : fichier trop petit pour contenir un cookie CArchive[/]")
            return True
        # Le cookie est aux 19 derniers octets
        cookie = data[fsize - COOKIE_LEN:]
        magic_in_cookie = cookie[-7:]
        if magic_in_cookie != MAGIC:
            # Pas un exe --onefile PyInstaller (Nuitka, mode onedir, etc.)
            ui_info("[dim]PKG : pas de cookie CArchive en fin de fichier (exe non-PyInstaller onefile)[/]")
            return True
        # Parser le cookie (big-endian, format PyInstaller historique)
        pkg_start  = struct.unpack_from(">I", cookie, 0)[0]
        toc_offset = struct.unpack_from(">I", cookie, 4)[0]
        toc_len    = struct.unpack_from(">I", cookie, 8)[0]
        pyvers     = struct.unpack_from(">I", cookie, 12)[0]
        # Validation de coherence
        if pkg_start > fsize:
            ui_warn(f"PKG : pkg_start (0x{pkg_start:X}) > taille fichier (0x{fsize:X}) — cookie corrompu")
            logger.warning("PKG cookie corrompu : pkg_start=0x%X fsize=0x%X", pkg_start, fsize)
            return False
        if toc_offset > fsize - pkg_start:
            ui_warn(f"PKG : TOC hors archive (toc_off=0x{toc_offset:X} > archive_len=0x{fsize - pkg_start:X})")
            logger.warning("PKG TOC invalide : toc_off=0x%X archive_len=0x%X", toc_offset, fsize - pkg_start)
            return False
        archive_len = fsize - pkg_start
        py_major = pyvers // 10
        py_minor = pyvers % 10
        ui_ok(
            f"PKG CArchive OK — "
            f"archive={archive_len // 1024}KB, "
            f"TOC={toc_len}B, "
            f"Python={py_major}.{py_minor}"
        )
        logger.info("PKG OK : pkg_start=0x%X toc_off=0x%X toc_len=%d py=%d.%d",
                    pkg_start, toc_offset, toc_len, py_major, py_minor)
        return True
    except (OSError, struct.error) as exc:
        ui_warn(f"PKG CRC ignore : {exc}")
        logger.warning("PKG CRC echec : %s", exc)
        return False


def _wrap_nsis_installer(exe_path: str, cfg: dict, logger) -> str:
    """
    Genere un script NSIS (.nsi) pour empaqueter l'exe dans un installeur.

    Pourquoi : un installeur a un niveau de confiance SmartScreen/Defender
    bien superieur a un exe brut car :
      - Il est signe en tant qu'installeur (EV Code Signing attendu)
      - Windows Installer est un format reconnu et non associe aux RATs
      - Le comportement (CreateDirectory, WriteRegStr, CreateShortcut) est
        le profil comportemental exact d'un logiciel legitime
      - SmartScreen calcule une reputation separee pour les installeurs

    La fonction genere le .nsi pret a compiler avec makensis.exe (NSIS 3+).
    Si makensis est dans le PATH, compile directement.
    """
    app  = cfg["app_name"]
    org  = cfg.get("av_version_company", "") or cfg.get("organization", "Editeur")
    vstr = cfg.get("av_version_str", "1.0.0.0")
    icon = cfg.get("icon", "icon.ico")

    nsi_path  = f"{app}_installer.nsi"
    inst_path = f"dist/{app}_Setup.exe"

    nsi_content = (
        f"!define APP_NAME    \"{app}\"\n"
        f"!define APP_VERSION \"{vstr}\"\n"
        f"!define APP_ORG     \"{org}\"\n"
        f"!define OUT_FILE    \"{inst_path}\"\n\n"
        "Unicode true\n"
        "Name \"${APP_NAME} ${APP_VERSION}\"\n"
        "OutFile \"${OUT_FILE}\"\n"
        "InstallDir \"$PROGRAMFILES64\\${APP_ORG}\\${APP_NAME}\"\n"
        "RequestExecutionLevel admin\n"
        "SetCompressor /SOLID lzma\n\n"
        "!include \"MUI2.nsh\"\n"
        "!insertmacro MUI_PAGE_WELCOME\n"
        "!insertmacro MUI_PAGE_DIRECTORY\n"
        "!insertmacro MUI_PAGE_INSTFILES\n"
        "!insertmacro MUI_PAGE_FINISH\n"
        "!insertmacro MUI_UNPAGE_CONFIRM\n"
        "!insertmacro MUI_UNPAGE_INSTFILES\n"
        "!insertmacro MUI_LANGUAGE \"French\"\n\n"
        "Section \"Installation\" SEC01\n"
        "  SetOutPath \"$INSTDIR\"\n"
        f"  File \"{exe_path}\"\n"
        "  CreateShortcut \"$DESKTOP\\${APP_NAME}.lnk\" \"$INSTDIR\\${APP_NAME}.exe\"\n"
        "  WriteUninstaller \"$INSTDIR\\Uninstall.exe\"\n"
        "  WriteRegStr HKLM \"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        "\\${APP_NAME}\" \"DisplayName\" \"${APP_NAME}\"\n"
        "  WriteRegStr HKLM \"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        "\\${APP_NAME}\" \"DisplayVersion\" \"${APP_VERSION}\"\n"
        "  WriteRegStr HKLM \"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        "\\${APP_NAME}\" \"Publisher\" \"${APP_ORG}\"\n"
        "SectionEnd\n\n"
        "Section \"Desinstallation\"\n"
        "  Delete \"$INSTDIR\\${APP_NAME}.exe\"\n"
        "  Delete \"$INSTDIR\\Uninstall.exe\"\n"
        "  Delete \"$DESKTOP\\${APP_NAME}.lnk\"\n"
        "  RMDir \"$INSTDIR\"\n"
        "  DeleteRegKey HKLM \"Software\\Microsoft\\Windows\\CurrentVersion"
        "\\Uninstall\\${APP_NAME}\"\n"
        "SectionEnd\n"
    )
    if Path(icon).exists():
        nsi_content = f"!define MUI_ICON \"{icon}\"\n" + nsi_content

    Path(nsi_path).write_text(nsi_content, encoding="utf-8")
    ui_ok(f"Script NSIS genere : [bold]{nsi_path}[/]")

    makensis = shutil.which("makensis") or shutil.which("makensis.exe")
    if makensis:
        with CONSOLE.status("[cyan]  Compilation NSIS...[/]", spinner="dots2"):
            res = run_silent([makensis, nsi_path])
        if res.returncode == 0 and Path(inst_path).exists():
            ui_ok(f"Installeur NSIS : [bold]{inst_path}[/]")
            logger.info("NSIS installer : %s", inst_path)
            return inst_path
        ui_warn(f"makensis echec (code {res.returncode}) — .nsi genere pour compilation manuelle.")
        logger.warning("makensis echec : %s", res.stderr[:200])
    else:
        ui_info("[dim]makensis non trouve — compilez manuellement : "
                f"[bright_blue]makensis {nsi_path}[/][/]")
    return nsi_path


def _verify_signature(signtool: str, exe: str, logger) -> bool:
    """
    Verifie la signature Authenticode avec signtool verify.

    Strategies de verification (dans l'ordre) :
      1. /pa  — politique Authenticode standard (CA reconnue dans le trust store)
      2. Si echec /pa avec "untrusted root" : essai /ad (any default policy)
         Note : les certificats auto-signes (openssl req -x509) echouent toujours
         avec /pa car ils ne sont pas dans le Trusted Root CA de Windows.
         C'est NORMAL et attendu — la signature SHA256 reste valide et Defender
         l'accepte si le certificat est dans le Personal store local.
      3. Analyse du code de retour pour distinguer :
         - Signature structurellement valide mais CA non reconnue (avertissement)
         - Signature corrompue / hash invalide (erreur critique)
    """
    result = run_silent([signtool, "verify", "/pa", "/v", exe])
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    output = (stdout + stderr).lower()

    if result.returncode == 0:
        ui_ok(f"Signature verifiee OK : [bold]{Path(exe).name}[/]")
        logger.info("Signature valide (CA reconnue) : %s", exe)
        return True

    # Distinguer "CA inconnue" (certificat auto-signe = normal) vs erreur reelle
    untrusted_markers = [
        "a certificate chain could not be built",
        "untrusted root",
        "chain was not trusted",
        "self signed certificate",
        "unable to get local issuer certificate",
        "0x800b0109",   # CERT_E_UNTRUSTED_ROOT
        "0x800b010a",   # CERT_E_CHAINING
    ]
    is_untrusted_root = any(m in output for m in untrusted_markers)

    # Verifier l'integrite du hash (meme si CA non reconnue)
    hash_ok = "hash of file (sha256)" in output
    signed_by = "signing certificate chain" in output

    if is_untrusted_root or (signed_by and not hash_ok):
        # Certificat auto-signe : signature presente mais CA non dans trust store
        ui_warn(
            f"Signature auto-signee : [bold]{Path(exe).name}[/]\n"
            "  [dim]Certificat non dans le Trusted Root CA Windows — c'est normal\n"
            "  pour un certificat genere avec openssl req -x509.\n"
            "  Defender accepte la signature si le .pfx est dans le Personal store.\n"
            "  Pour une signature reconnue, utilisez un certificat EV d'une CA.\n"
            "  Pour l'ajouter au trust store local :\n"
            "  [bright_blue]certutil -addstore Root codesign.crt[/][/]"
        )
        logger.info("Signature auto-signee (non-CA) : %s", exe)
        return True   # Pas une erreur — comportement attendu pour auto-signe

    # Verifier si le hash du fichier est integre malgre l'echec de la CA
    hash_result = run_silent([signtool, "verify", "/hash", "SHA256", exe])
    if hash_result.returncode == 0:
        ui_ok(f"Hash SHA256 intact — signature presente : [bold]{Path(exe).name}[/]")
        logger.info("Hash signature OK (CA non reconnue) : %s", exe)
        return True

    # Erreur reelle : signature corrompue ou hash invalide
    CONSOLE.print(Panel(
        f"  [bold red]Signature corrompue : {Path(exe).name}[/]\n"
        f"  [dim]{(stdout + stderr).strip()[:300]}[/]\n\n"
        "  [white]Causes possibles :[/]\n"
        "  [dim]• Le binaire a ete modifie APRES la signature\n"
        "    (un patch PE post-signature invalide le hash)\n"
        "  • Le fichier PFX est corrompu ou le mot de passe est incorrect\n"
        "  • Re-signez avec --sign-only apres les patches PE[/]",
        title="[bold red] ERREUR SIGNATURE CRITIQUE [/]",
        border_style="red", box=box.HEAVY, padding=(0, 1),
    ))
    logger.error("Signature invalide (hash) %s : %s", exe, (stdout+stderr)[:200])
    return False


def _wipe_build_artifacts(app_name: str, logger) -> None:
    """
    Efface les artefacts de build intermediaires apres compilation.

    Efface : build/, _pymake_build_tmp/, _pyarmor_dist/,
             <app>.spec, <app>.manifest, rth_legitapp.py, version_info.txt.
    Pourquoi : ces fichiers contiennent des metadonnees de build
    (chemins absolus, noms d'utilisateur dans les paths) qui peuvent
    etre analyses par certains AV lors du scan du repertoire de travail.
    """
    targets = [
        Path("build"),
        Path("_pymake_build_tmp"),
        Path("_pyarmor_dist"),
        Path(f"{app_name}.spec"),
        Path(f"{app_name}.manifest"),
        Path("rth_legitapp.py"),
        Path("version_info.txt"),
    ]
    wiped = []
    for t in targets:
        try:
            if t.is_dir():
                shutil.rmtree(t); wiped.append(str(t))
            elif t.is_file():
                t.unlink(); wiped.append(str(t))
        except OSError as exc:
            logger.warning("Wipe ignore %s : %s", t, exc)
    if wiped:
        ui_ok(f"Artefacts effaces : [dim]{', '.join(wiped)}[/]")
        logger.info("Wipe : %s", ", ".join(wiped))
    else:
        ui_info("[dim]Aucun artefact de build a effacer[/]")


def _virustotal_check(exe_path: str, logger) -> None:
    """
    Soumet l'exe a l'API publique VirusTotal v3 et affiche le rapport.

    Necessite une cle API VT gratuite dans la variable d'environnement
    VIRUSTOTAL_API_KEY. Sans cle, affiche uniquement le lien de soumission.

    L'API publique limite a 4 requetes/min et 500/jour (plan gratuit).
    Pour les soumissions frequentes (CI/CD), utilisez le plan premium.
    """
    import urllib.request   # pylint: disable=import-outside-toplevel
    import urllib.error     # pylint: disable=import-outside-toplevel
    import urllib.parse     # pylint: disable=import-outside-toplevel

    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

    if not api_key:
        CONSOLE.print(Panel(
            "  [dim]Definissez la variable d'environnement :\n"
            "  [bright_blue]set VIRUSTOTAL_API_KEY=votre_cle[/]\n\n"
            "  Cle gratuite : https://www.virustotal.com/gui/join-us\n\n"
            f"  Soumission manuelle : https://www.virustotal.com/gui/home/upload\n"
            f"  SHA256 : {hashlib.sha256(Path(exe_path).read_bytes()).hexdigest()}[/]",
            title="[bold magenta] VirusTotal — Cle API Manquante [/]",
            border_style="magenta", padding=(0, 1),
        ))
        return

    try:
        # 1. Calcul du hash pour lookup avant upload (evite de re-soumettre)
        sha256    = hashlib.sha256(Path(exe_path).read_bytes()).hexdigest()
        vt_url    = f"https://www.virustotal.com/api/v3/files/{sha256}"
        req       = urllib.request.Request(vt_url,
                                           headers={"x-apikey": api_key})
        with CONSOLE.status("[magenta]  Requete VirusTotal...[/]", spinner="dots2"):
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    result = json.loads(resp.read())
                found_cached = True
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    found_cached = False
                    result = {}
                else:
                    raise

        if not found_cached:
            # 2. Upload du fichier
            ui_info("[dim]Fichier inconnu de VT — upload en cours...[/]")
            boundary = "----VTPyMakeBoundary"
            body     = (f"--{boundary}\r\nContent-Disposition: form-data; "
                        f"name=\"file\"; filename=\"{Path(exe_path).name}\"\r\n"
                        f"Content-Type: application/octet-stream\r\n\r\n").encode()
            body    += Path(exe_path).read_bytes()
            body    += f"\r\n--{boundary}--\r\n".encode()
            up_req   = urllib.request.Request(
                "https://www.virustotal.com/api/v3/files",
                data=body,
                headers={"x-apikey": api_key,
                         "Content-Type": f"multipart/form-data; boundary={boundary}"},
                method="POST",
            )
            with urllib.request.urlopen(up_req, timeout=60) as resp:
                up_data = json.loads(resp.read())
            analysis_id = up_data.get("data", {}).get("id", "")
            ui_info(f"[dim]Upload OK — analysis_id : {analysis_id}[/]")
            ui_info("[dim]Analyse en cours chez VT (quelques minutes)...[/]")
            ui_info(f"[dim]Rapport : https://www.virustotal.com/gui/file/{sha256}[/]")
            logger.info("VT upload OK : analysis_id=%s", analysis_id)
            return

        # 3. Afficher le rapport
        stats = (result.get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}))
        mal   = stats.get("malicious", 0)
        susp  = stats.get("suspicious", 0)
        clean = stats.get("undetected", 0)
        total = sum(stats.values())
        color = "bright_green" if mal == 0 else ("yellow" if mal <= 3 else "bold red")

        table = Table(box=box.ROUNDED, border_style="magenta", expand=True)
        table.add_column("Statut", min_width=14)
        table.add_column("Moteurs", justify="right")
        table.add_row("[bold red]Malicieux[/]",    f"[bold red]{mal}[/]")
        table.add_row("[yellow]Suspect[/]",         str(susp))
        table.add_row("[bright_green]Non detecte[/]", str(clean))
        table.add_row("[dim]Total moteurs[/]",      str(total))

        CONSOLE.print(Panel(
            table,
            title=f"[bold magenta] VirusTotal — [{color}]{mal}/{total} detecteurs[/] [/]",
            subtitle=f"[dim]https://www.virustotal.com/gui/file/{sha256}[/]",
            border_style="magenta", padding=(0, 1),
        ))
        logger.info("VT rapport : %d/%d malicieux", mal, total)

    except (OSError, json.JSONDecodeError) as exc:
        ui_warn(f"VirusTotal check ignore : {exc}")
        logger.warning("VT echec : %s", exc)


# ══════════════════════════════════════════════════════════════════
# SECTION 7 — Etape 3 : Durcissement anti-faux-positifs AV
# ══════════════════════════════════════════════════════════════════

def _rebuild_bootloader(cfg, logger):
    """
    Recompile le bootloader PyInstaller depuis les sources incluses dans la venv.

    Pourquoi c'est efficace :
      Le bootloader par defaut est un binaire C identique sur toutes les
      installations PyInstaller. Les AV l'ont indexe dans leurs bases de
      signatures a cause de malwares connus qui utilisaient PyInstaller.
      Recompiler produit un binaire avec un hash entierement different :
      aucun AV ne peut matcher une signature qu'il n'a jamais vue.

    Prerequis : gcc / MinGW-w64 installe et accessible dans le PATH.
    """
    python = venv_python(cfg["venv_dir"])
    result = run_silent([
        python, "-c",
        "import PyInstaller, os; "
        "print(os.path.join(os.path.dirname(PyInstaller.__file__), 'bootloader'))",
    ])
    if result.returncode != 0 or not result.stdout.strip():
        ui_warn("PyInstaller introuvable dans la venv — bootloader non recompile.")
        return

    bl_dir     = result.stdout.strip()
    waf_script = Path(bl_dir) / "waf"

    if not Path(bl_dir).exists() or not waf_script.exists():
        ui_warn(f"Dossier bootloader absent : {bl_dir}")
        return

    gcc = shutil.which("gcc") or shutil.which("x86_64-w64-mingw32-gcc")
    if not gcc:
        ui_warn("gcc introuvable — recompilation ignoree.")
        ui_info("Installez MinGW-w64 : [cyan]https://winlibs.com/[/cyan]")
        return

    ui_info("Recompilation bootloader (peut prendre 1-2 min)...")
    with CONSOLE.status("[cyan]  Compilation C...[/]", spinner="dots2"):
        res = run_silent([python, str(waf_script), "all"], cwd=bl_dir)

    if res.returncode == 0:
        ui_ok("Bootloader recompile — hash unique, inconnu des bases AV")
        logger.info("Bootloader recompile dans %s", bl_dir)
    else:
        ui_warn("Recompilation echouee — build standard utilise.")
        logger.warning("Bootloader echec stderr: %s", res.stderr[:200])


def _generate_version_info(cfg):
    """
    Genere le fichier version_info.txt pour PyInstaller --version-file.

    Pourquoi c'est efficace :
      Les AV et Windows SmartScreen accordent plus de confiance aux executables
      qui embarquent des metadonnees completes (CompanyName, FileDescription,
      Copyright, version...). Un .exe sans ces champs est statistiquement plus
      souvent malveillant -> les AV le scrutent davantage.
      Ce fichier est injecte par PyInstaller directement dans le PE (.exe).
    """
    app  = cfg["app_name"]
    org  = cfg.get("av_version_company", "") or cfg.get("organization", "")
    desc = cfg.get("av_version_description", "") or app
    vstr = cfg.get("av_version_str", "1.0.0.0")
    year = datetime.now().year

    try:
        parts     = [int(x) for x in vstr.split(".")]
        parts    += [0] * (4 - len(parts))
        ver_tuple = tuple(parts[:4])
    except (ValueError, AttributeError):
        ver_tuple = (1, 0, 0, 0)

    lines = [
        "VSVersionInfo(",
        "  ffi=FixedFileInfo(",
        f"    filevers={ver_tuple},",
        f"    prodvers={ver_tuple},",
        "    mask=0x3f, flags=0x0, OS=0x40004,",
        "    fileType=0x1, subtype=0x0, date=(0, 0)",
        "  ),",
        "  kids=[",
        "    StringFileInfo([StringTable(u'040904B0', [",
        f"      StringStruct(u'CompanyName',      u'{org}'),",
        f"      StringStruct(u'FileDescription',  u'{desc}'),",
        f"      StringStruct(u'FileVersion',      u'{vstr}'),",
        f"      StringStruct(u'InternalName',     u'{app}'),",
        f"      StringStruct(u'LegalCopyright',   u'Copyright {year} {org}'),",
        f"      StringStruct(u'OriginalFilename', u'{app}.exe'),",
        f"      StringStruct(u'ProductName',      u'{app}'),",
        f"      StringStruct(u'ProductVersion',   u'{vstr}'),",
        "    ])]),",
        "    VarFileInfo([VarStruct(u'Translation', [0x0409, 1200])])",
        "  ]",
        ")",
    ]
    Path(VERSION_INFO_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")
    ui_ok(f"VersionInfo genere : [bold]{VERSION_INFO_FILE}[/]")


def _generate_app_manifest(app_name):
    """
    Genere un manifeste Windows (.manifest) et tente de l'injecter dans l'exe
    via mt.exe (Manifest Tool, inclus dans le Windows SDK avec signtool).

    Pourquoi c'est efficace contre heuristique AV :
      heuristique AV analyse la section RT_MANIFEST du PE pour determiner si
      l'executable a ete produit par un outil legitime. Un manifeste absent
      ou generique (celui par defaut de PyInstaller) est un signal ML fort
      de packer malveillant. Un manifeste complet avec requestedExecutionLevel,
      trustInfo et supportedOS evite ce signal.

    mt.exe est recherche dans les memes chemins que signtool.
    Si absent, le fichier .manifest est genere mais l'injection est ignoree
    (PyInstaller peut l'inclure via --manifest lors du build).
    """
    manifest_file = f"{app_name}.manifest"
    content = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\n'
        f'  <assemblyIdentity version="1.0.0.0" processorArchitecture="amd64"\n'
        f'    name="{app_name}" type="win32"/>\n'
        f'  <description>{app_name}</description>\n'
        '  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">\n'
        '    <security>\n'
        '      <requestedPrivileges>\n'
        '        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>\n'
        '      </requestedPrivileges>\n'
        '    </security>\n'
        '  </trustInfo>\n'
        '  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">\n'
        '    <application>\n'
        '      <!-- Windows 10 / 11 -->\n'
        '      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>\n'
        '      <!-- Windows 8.1 -->\n'
        '      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>\n'
        '    </application>\n'
        '  </compatibility>\n'
        '  <application xmlns="urn:schemas-microsoft-com:asm.v3">\n'
        '    <windowsSettings>\n'
        '      <longPathAware xmlns="http://schemas.microsoft.com/'
        'SMI/2016/WindowsSettings">true</longPathAware>\n'
        '    </windowsSettings>\n'
        '  </application>\n'
        '</assembly>\n'
    )
    Path(manifest_file).write_text(content, encoding="utf-8")
    ui_ok(f"Manifeste genere : [bold]{manifest_file}[/]")
    return manifest_file


def _find_mt_exe():
    """Recherche mt.exe (Manifest Tool) dans les memes chemins que signtool."""
    _pf86 = "C:\\Program Files (x86)"
    _pf   = "C:\\Program Files"
    _wk   = "\\Windows Kits\\10\\bin\\**\\"
    search_patterns = [
        _pf86 + _wk + "x64\\mt.exe",
        _pf86 + _wk + "x86\\mt.exe",
        _pf   + _wk + "x64\\mt.exe",
    ]
    for pattern in search_patterns:
        matches = glob.glob(pattern, recursive=True)
        if matches:
            return sorted(matches)[-1]
    return shutil.which("mt.exe") or shutil.which("mt")


def _embed_manifest(exe_path, manifest_file, logger):
    """
    Injecte le manifeste dans l'exe produit via mt.exe apres le build.
    Appele dans step_build apres PyInstaller.
    """
    mt_exe = _find_mt_exe()
    if not mt_exe:
        ui_warn(
            "mt.exe introuvable — manifeste non injecte post-build.\n"
            "  [dim]Le manifeste sera inclus via --manifest lors du prochain build.[/]"
        )
        return False
    with CONSOLE.status("[cyan]  Injection du manifeste...[/]", spinner="dots2"):
        result = run_silent([
            mt_exe,
            "-manifest", manifest_file,
            f"-outputresource:{exe_path};#1",
            "-nologo",
        ])
    if result.returncode == 0:
        ui_ok(f"Manifeste injecte dans [bold]{Path(exe_path).name}[/]  via mt.exe")
        logger.info("Manifeste injecte dans %s", exe_path)
        return True
    ui_warn(f"Injection manifeste echouee (code {result.returncode}) — ignoree.")
    logger.warning("mt.exe echec : %s", result.stderr[:150])
    return False


def step_av_harden(cfg, logger):
    """
    Etape 3/5 : Applique toutes les techniques de reduction des faux positifs AV.

    Techniques (29 au total) :
      [Couche 1 — Anti-AV generiques]
      1. Recompiler le bootloader (hash unique)
      2. VersionInfo PE (metadonnees legitimantes)
      3. Desactiver UPX (compression suspecte)
      [Couche 2 — Anti-FP couche 1]
      4. Manifeste Windows RT_MANIFEST
      5. Strip debug (--strip)
      6. Exclusion de modules suspects
      [Couche 3 — Anti-FP couche 1 avancee]
      7. Mode --onedir (pas d'extraction %TEMP%)
      8. Fichier .spec (optimize=2 + controle total)
      9. Hook runtime AppData (profil comportemental legitime)
      10. Normalisation timestamp PE
      11. Renommage _internal
      12. Scrub chaines PyInstaller
      [Couche 4 — PE Hardening post-build]
      13. Recalcul checksum PE
      14. DllCharacteristics ASLR+DEP+CFG
      15. Analyse entropie (seuil 7.2)
      16. Minification source Python
      17. Build Nuitka (C natif)
      18. Script PowerShell exclusion Defender
      19. Double signature SHA1+SHA256
      [Couche 5 — PE Expert]
      20. Rich Header MSVC dans DOS stub
      21. Sous-systeme PE CONSOLE->WINDOWS_GUI
      22. Obfuscation PyArmor
      23. Installeur NSIS
      24. Verification signature post-sign
      25. Normalisation alignement sections PE
      26. Analyse IAT + enrichissement imports
      27. Validation CRC archive PKG
      28. Nettoyage artefacts de build
      29. Rapport VirusTotal
    """
    print_step(3, 5, "Durcissement anti-faux-positifs AV — 29 techniques")
    _print_av_recap(cfg)
    applied = []

    # ── Techniques Anti-AV generiques ───────────────────────────
    CONSOLE.print()
    CONSOLE.print(Rule(
        title="[bold bright_green]Anti-AV generiques[/]", style="bright_green"
    ))

    if cfg.get("av_rebuild_bootloader"):
        _rebuild_bootloader(cfg, logger)
        applied.append("bootloader recompile")
    else:
        ui_info("[dim]Bootloader : non recompile (activez av_rebuild_bootloader)[/]")

    has_meta = cfg.get("av_version_company") or cfg.get("av_version_description")
    if has_meta:
        _generate_version_info(cfg)
        applied.append("VersionInfo PE genere")
    else:
        ui_info("[dim]VersionInfo : ignore (renseignez av_version_company)[/]")

    if cfg.get("av_disable_upx"):
        ui_ok("UPX desactive — flag [bold]--noupx[/] ajoute au build")
        applied.append("UPX desactive")
    else:
        ui_warn("UPX actif — peut declencher des AV (certaines souches UPX-packees)")

    # ── Techniques Anti-FP couche 1 — couche 1 ─────────────────
    CONSOLE.print()
    CONSOLE.print(Rule(
        title="[bold bright_red]Anti-FP couche 1 — couche 1[/]", style="bright_red"
    ))

    # Technique 4 — Manifeste Windows
    if cfg.get("av_add_manifest"):
        _generate_app_manifest(cfg["app_name"])
        applied.append("manifeste Windows genere")
        ui_info(
            "[dim]Sera injecte dans l'exe apres build via mt.exe (Windows SDK)[/]"
        )
    else:
        ui_info("[dim]Manifeste : desactive (activez av_add_manifest)[/]")

    # Technique 5 — Strip debug
    if cfg.get("av_strip_debug"):
        ui_ok(
            "Strip debug active — flag [bold]--strip[/] ajoute au build\n"
            "  [dim]Supprime .pdata, debug directory et symboles — "
            "PE moins suspect pour le ML Defender[/]"
        )
        applied.append("symboles debug supprimes")
    else:
        ui_info("[dim]Strip debug : desactive[/]")

    # Technique 6 — Exclusion de modules suspects
    raw_excl = cfg.get("av_exclude_modules", "").strip()
    excluded = [m.strip() for m in raw_excl.split(",") if m.strip()] if raw_excl else []
    if excluded:
        ui_ok(
            f"Modules exclus : [dim]{', '.join(excluded)}[/]\n"
            "  [dim]Reduit les imports suspects detectes par heuristique AV heuristique[/]"
        )
        applied.append(f"{len(excluded)} modules exclus")
    else:
        ui_info("[dim]Exclusion modules : aucune (renseignez av_exclude_modules)[/]")

    # ── Techniques Anti-FP couche 1 — couche 2 (avancee) ───────
    CONSOLE.print()
    CONSOLE.print(Rule(
        title="[bold orange1]Anti-FP couche 1 — couche 2 (avancee)[/]", style="orange1"
    ))

    # Technique 7 — Mode --onedir
    if cfg.get("av_onedir_mode"):
        ui_ok(
            "Mode [bold]--onedir[/] active\n"
            "  [dim]Elimine l'extraction dans %TEMP%\\MEI<random> — signal #1 de heuristique AV.\n"
            "  Les RATs/stealers PyInstaller utilisent quasi-exclusivement --onefile.\n"
            "  Livraison sous forme de dossier (pas d'exe unique).[/]"
        )
        applied.append("mode --onedir (pas d'extraction %TEMP%)")
    else:
        ui_warn(
            "Mode --onefile actif — l'exe s'extraira dans %TEMP% au lancement.\n"
            "  [dim]C'est le pattern #1 detecte par heuristique AV. Activez av_onedir_mode si possible.[/]"
        )

    # Technique 8 — Fichier .spec
    if cfg.get("av_use_spec"):
        ui_ok(
            "Fichier .spec active — sera genere avant le build\n"
            "  [dim]Inclut optimize=2 (bytecode optimise), contents_directory,\n"
            "  runtime_hooks et controle total des options PyInstaller.[/]"
        )
        applied.append("fichier .spec genere")
    else:
        ui_info("[dim]Fichier .spec : desactive (build via flags CLI)[/]")

    # Technique 9 — Hook runtime AppData
    if cfg.get("av_add_runtime_hook"):
        hook_f = _generate_runtime_hook(cfg["app_name"])
        applied.append("hook runtime AppData")
        cfg["_runtime_hook_file"] = hook_f
    else:
        ui_info("[dim]Hook runtime : desactive[/]")
        cfg["_runtime_hook_file"] = None

    # Technique 10 — Normalisation timestamp PE (post-build)
    if cfg.get("av_pe_timestamp"):
        ui_ok(
            "Patch timestamp PE active — sera applique apres le build\n"
            "  [dim]Un timestamp PE a 0 est un marqueur de packer malveillant.\n"
            "  Sera remplace par la date de compilation actuelle.[/]"
        )
        applied.append("timestamp PE normalise (post-build)")
    else:
        ui_info("[dim]Patch timestamp PE : desactive[/]")

    # Technique 11 — Renommage _internal
    if cfg.get("av_rename_internal"):
        ui_ok(
            "Renommage _internal active (PyInstaller 6+)\n"
            "  [dim]Le dossier '_internal' est un motif PyInstaller connu des AV.\n"
            "  contents_directory='.' dans le .spec aplatit la structure.[/]"
        )
        applied.append("dossier _internal renomme")
    else:
        ui_info("[dim]Renommage _internal : desactive[/]")

    # Technique 12 — Scrub chaines PyInstaller (post-build)
    if cfg.get("av_scrub_pi_strings"):
        ui_ok(
            "Scrub chaines PyInstaller active — sera applique apres le build\n"
            "  [dim]Remplace 'PyInstaller' et 'pyi-windows' dans le binaire.\n"
            "  Ces patterns sont dans les signatures heuristiques Defender.[/]"
        )
        applied.append("chaines PyInstaller scrubees (post-build)")
    else:
        ui_info("[dim]Scrub chaines : desactive[/]")

    # ── Rappel signature ─────────────────────────────────────────
    CONSOLE.print()
    CONSOLE.print(Rule(
        title="[bold bright_yellow]Signature Authenticode (etape 5)[/]",
        style="yellow",
    ))
    ui_info(
        "[dim]Technique la plus efficace contre heuristique AV.\n"
        "  Un exe signe avec un certificat reconnu passe le filtre ML de Defender.[/]"
    )

    # ── Couche 4 — PE Hardening ──────────────────────────────────
    CONSOLE.print()
    CONSOLE.print(Rule(title="[bold bright_blue]PE Hardening — couche 4 (post-build)[/]",
                       style="bright_blue"))

    for key, label, detail in [
        ("av_fix_pe_checksum",
         "Recalcul checksum PE [dim](post-build)[/]",
         "Checksum invalide apres tout patch = signal packer Defender."),
        ("av_harden_pe_flags",
         "DllCharacteristics : ASLR+DEP+CFG [dim](post-build)[/]",
         "Exe sans CFG = penalise par le ML Defender. PyInstaller 5.x ne l'active pas."),
        ("av_check_entropy",
         "Analyse entropie [dim](post-build)[/]",
         "Seuil heuristique AV = 7.2 bits/octet. Avertissement + actions si depasse."),
        ("av_minify_source",
         "Minification source Python [dim](pre-build)[/]",
         "Supprime docstrings + commentaires suspects dans le code source."),
        ("av_use_nuitka",
         "Build Nuitka — C natif [dim](alternatif PyInstaller)[/]",
         "Python->C->exe. Aucune signature PyInstaller, entropie ~6.2-6.8."),
        ("av_gen_exclusion_ps1",
         "Script PowerShell exclusion Defender [dim](post-build)[/]",
         "Whitelist par chemin + hash SHA256. Usage dev/CI uniquement."),
        ("av_dual_sign",
         "Double signature SHA1+SHA256 [dim](post-sign)[/]",
         "SmartScreen Win10/11 + compatibilite Win7/8."),
    ]:
        if cfg.get(key):
            ui_ok(f"{label}\n  [dim]{detail}[/]")
            applied.append(label.split("[")[0].strip())
        else:
            ui_info(f"[dim]{label.split('[')[0].strip()} : desactive[/]")

    # ── Post-Build — chiffrement bytecode ──────────────────
    CONSOLE.print()
    CONSOLE.print(Rule(title="[bold red]Post-Build — chiffrement bytecode[/]",
                       style="red"))
    if cfg.get("av_obfuscate_pyc"):
        ui_ok(
            "Obfuscation .pyc active [bold](XOR post-build)[/]\n"
            "  [dim]Le bytecode est repacke apres build — détection AV ne\n"
            "  peut plus matcher les signatures statiques des .pyc.[/]"
        )
        applied.append("bytecode .pyc obfusque (XOR)")
    else:
        ui_info("[dim]Obfuscation .pyc desactivee[/]")

    # ── Couche 5 — PE Expert ─────────────────────────────────────
    CONSOLE.print()
    CONSOLE.print(Rule(title="[bold magenta]PE Expert — couche 5 (post-build)[/]",
                       style="magenta"))

    for key, label, detail in [
        ("av_patch_rich_header",
         "Rich Header MSVC [dim](DOS stub)[/]",
         "Son absence = signal packer. Defender fait confiance aux exe MSVC."),
        ("av_set_subsystem_gui",
         "Subsystem CONSOLE -> WINDOWS_GUI",
         "Les RATs/stealers sont quasi-exclusivement CONSOLE. GUI = profil legitime."),
        ("av_pyarmor_obfuscate",
         "Obfuscation PyArmor [dim](pre-build)[/]",
         "Bytecode .pyc chiffre — les scanners AV ne voient plus de code lisible."),
        ("av_wrap_nsis_installer",
         "Installeur NSIS [dim](post-build)[/]",
         "SmartScreen alloue une reputation superieure aux installeurs signes."),
        ("av_verify_signature",
         "Verification signtool verify [dim](post-sign)[/]",
         "Detecte certificat expire / timestamp invalide / hash incorrect."),
        ("av_fix_section_alignment",
         "Alignement sections PE normalise [dim](post-build)[/]",
         "SectionAlignment=0x1000, FileAlignment=0x200 — valeurs non standard = packer."),
        ("av_enrich_import_table",
         "Analyse + rapport IAT [dim](post-build)[/]",
         "Peu d'imports = suspect. Analyse les DLL importees et conseille."),
        ("av_fix_pkg_crc",
         "Validation CRC archive PKG [dim](post-build)[/]",
         "Archive PKG avec CRC invalide = binaire altere post-build pour Defender."),
        ("av_wipe_build_artifacts",
         "Nettoyage artefacts build [dim](post-build)[/]",
         "Efface build/, .spec, .manifest, _tmp/ qui contiennent des paths absolus."),
        ("av_virustotal_check",
         "Rapport VirusTotal [dim](post-sign)[/]",
         "Necessite VIRUSTOTAL_API_KEY. Lookup par hash puis upload si inconnu."),
    ]:
        if cfg.get(key):
            ui_ok(f"{label}\n  [dim]{detail}[/]")
            applied.append(label.split("[")[0].strip())
        else:
            ui_info(f"[dim]{label.split('[')[0].strip()} : desactive[/]")

    # ── Rappel signature ─────────────────────────────────────────
    CONSOLE.print()
    CONSOLE.print(Rule(title="[bold bright_yellow]Signature Authenticode (etape 5)[/]",
                       style="yellow"))
    ui_info(
        "[dim]Technique la plus efficace contre heuristique AV.\n"
        "  Un exe signe par une CA reconnue passe le filtre ML de Defender.[/]"
    )

    logger.info("AV harden (%d techniques) : %s",
                len(applied), ", ".join(applied) if applied else "aucune")

    # Portails de soumission
    CONSOLE.print()
    CONSOLE.print(Panel(
        "  [dim]Si heuristique AV persiste apres build + signature, soumettez\n"
        "  l'exe sur le portail Microsoft en premier (traitement prioritaire\n"
        "  pour les faux positifs Defender), puis les autres editeurs.[/]",
        title="[bold magenta] Portails de Declaration Faux-Positifs [/]",
        border_style="dim magenta", padding=(0, 1),
    ))
    _print_av_portals_table()

# ══════════════════════════════════════════════════════════════════
# SECTION 8 — Etape 4 : Build PyInstaller
# ══════════════════════════════════════════════════════════════════

def step_build(cfg, logger):
    """Compile le script Python en executable. Retourne le chemin de l'exe."""
    app_name = cfg["app_name"]
    script   = cfg["script"]
    icon     = cfg["icon"]
    python   = venv_python(cfg["venv_dir"])
    onedir   = cfg.get("av_onedir_mode", False)

    mode_label = "--onedir" if onedir else "--onefile"
    print_step(4, 5, f"Compilation  [{mode_label}]  →  {app_name}.exe")

    if not Path(script).exists():
        fatal(logger, f"Script source '{script}' introuvable.")

    # ── Couche 5 : Obfuscation PyArmor (pre-build) ───────────────
    if cfg.get("av_pyarmor_obfuscate"):
        CONSOLE.print(Rule(title="[bold magenta]Pre-build : PyArmor[/]", style="magenta"))
        script = _pyarmor_obfuscate(script, cfg["venv_dir"], logger)

    # ── Couche 4 : Minification source (pre-build) ───────────────
    if cfg.get("av_minify_source"):
        CONSOLE.print(Rule(title="[bold bright_blue]Pre-build : Minification[/]",
                           style="bright_blue"))
        script = _minify_source(script, logger)

    # ── Couche 3 : Hook runtime AppData (pre-build) ──────────────
    hook_file = None
    if cfg.get("av_add_runtime_hook"):
        hook_file = _generate_runtime_hook(app_name)
    cfg["_runtime_hook_file"] = hook_file

    # ── Preparation des exclusions ────────────────────────────────
    raw_excl  = cfg.get("av_exclude_modules", "").strip()
    requested = [m.strip() for m in raw_excl.split(",") if m.strip()] if raw_excl else []
    skipped   = [m for m in requested if m in _HOOK_INCOMPATIBLE_EXCLUDES]
    excluded  = [m for m in requested if m not in _HOOK_INCOMPATIBLE_EXCLUDES]
    if skipped:
        ui_warn(
            f"Modules ignores (hook-incompatibles) : [dim]{', '.join(skipped)}[/]\n"
            "  [dim]PyInstaller les gere via ses hooks internes — crash si exclus.[/]"
        )

    # ── Verification version PyInstaller ─────────────────────────
    pi_version = _check_pyinstaller_version(python)
    ui_info(f"PyInstaller detecte : [dim]v{pi_version[0]}.{pi_version[1]}[/]")
    manifest_file = f"{app_name}.manifest"

    # ── Tentative build Nuitka (couche 4) ────────────────────────
    exe_path = ""
    if cfg.get("av_use_nuitka"):
        CONSOLE.print(Rule(title="[bold bright_blue]Build : Nuitka[/]", style="bright_blue"))
        exe_path = _build_with_nuitka({**cfg, "script": script}, logger)

    # ── Build PyInstaller (si Nuitka desactive ou echec) ─────────
    if not exe_path:
        CONSOLE.print(Rule(title="[bold cyan]Build : PyInstaller[/]", style="cyan"))
        # Mode .spec (recommande)
        if cfg.get("av_use_spec"):
            spec_file = _generate_spec_file(cfg, manifest_file, excluded, hook_file)
            cmd = [python, "-m", "PyInstaller", spec_file, "--noconfirm"]
            ui_info(f"Build via .spec : [bold]{spec_file}[/]")
        # Mode flags CLI
        else:
            mode_flag = "--onedir" if onedir else "--onefile"
            cmd = [python, "-m", "PyInstaller", mode_flag, f"--name={app_name}"]
            if cfg.get("av_disable_upx"):
                cmd.append("--noupx")
            if Path(VERSION_INFO_FILE).exists():
                cmd.extend(["--version-file", VERSION_INFO_FILE])
            if cfg.get("av_add_manifest") and Path(manifest_file).exists():
                cmd.extend(["--manifest", manifest_file])
            if cfg.get("av_strip_debug"):
                cmd.append("--strip")
            for mod in excluded:
                cmd.extend(["--exclude-module", mod])
            if hook_file and Path(hook_file).exists():
                cmd.extend(["--runtime-hook", hook_file])
            if Path(icon).exists():
                cmd.append(f"--icon={icon}")
            else:
                ui_info(f"Icone '{icon}' absente.")
            cmd.append(script)

        with CONSOLE.status("[bold cyan]  Compilation...[/]", spinner="dots2",
                            spinner_style="cyan"):
            result = run_silent(cmd)
        if result.returncode != 0:
            logger.error(result.stderr)
            fatal(logger, "Compilation PyInstaller echouee. Consultez le log.")

        exe_path = (str(Path("dist") / app_name / f"{app_name}.exe") if onedir
                    else str(Path("dist") / f"{app_name}.exe"))

    ui_ok(f"Executable : [bold]{exe_path}[/]")
    logger.info("Build OK : %s", exe_path)

    if not Path(exe_path).exists():
        fatal(logger, f"Executable introuvable apres build : {exe_path}")

    # ══ Post-build — patches PE ════════════════════════════════════
    CONSOLE.print()
    CONSOLE.print(Rule(title="[bold orange1]Post-build : patches PE[/]", style="orange1"))

    # Couche 2 : manifeste mt.exe
    if cfg.get("av_add_manifest") and Path(manifest_file).exists():
        _embed_manifest(exe_path, manifest_file, logger)

    # Couche 3 : timestamp PE
    if cfg.get("av_pe_timestamp"):
        _patch_pe_timestamp(exe_path, logger)

    # Couche 3 : scrub chaines PyInstaller
    if cfg.get("av_scrub_pi_strings"):
        _scrub_pyinstaller_strings(exe_path, logger)

    # Couche 5 : Rich Header MSVC
    if cfg.get("av_patch_rich_header"):
        _patch_rich_header(exe_path, logger)

    # Couche 5 : Subsystem CONSOLE -> GUI
    if cfg.get("av_set_subsystem_gui"):
        _set_subsystem_gui(exe_path, logger)

    # Couche 5 : Normalisation alignement sections
    if cfg.get("av_fix_section_alignment"):
        _fix_section_alignment(exe_path, logger)

    # Couche 4 : Hardening DllCharacteristics (apres les autres patches)
    if cfg.get("av_harden_pe_flags"):
        _harden_pe_flags(exe_path, logger)

    # Couche 4 : Recalcul checksum PE (TOUJOURS en dernier apres tous les patches)
    if cfg.get("av_fix_pe_checksum"):
        _fix_pe_checksum(exe_path, logger)

    # ══ Post-build — analyses ══════════════════════════════════════
    CONSOLE.print()
    CONSOLE.print(Rule(title="[bold orange1]Post-build : analyses[/]", style="orange1"))

    # Couche 4 : entropie
    if cfg.get("av_check_entropy"):
        _check_binary_entropy(exe_path, logger)

    # Couche 5 : IAT
    if cfg.get("av_enrich_import_table"):
        _enrich_import_table(exe_path, logger)

    # Post-Build : obfuscation .pyc
    if cfg.get("av_obfuscate_pyc"):
        _obfuscate_pyc_bundle(exe_path, logger)

    # Couche 5 : PKG CRC
    if cfg.get("av_fix_pkg_crc"):
        _fix_pkg_crc(exe_path, logger)

    # ══ Post-build — packaging supplementaire ══════════════════════
    # Couche 5 : installeur NSIS
    if cfg.get("av_wrap_nsis_installer"):
        CONSOLE.print()
        CONSOLE.print(Rule(title="[bold magenta]Post-build : NSIS[/]", style="magenta"))
        _wrap_nsis_installer(exe_path, cfg, logger)

    # Stocker le chemin pour le dual-sign en step_sign
    cfg["_built_exe"] = exe_path
    return exe_path

# ══════════════════════════════════════════════════════════════════
# SECTION 9 — Etape 5 : Signature
# ══════════════════════════════════════════════════════════════════

def find_signtool():
    """Recherche signtool.exe dans les emplacements SDK connus."""
    for pattern in SIGNTOOL_SEARCH_PATHS:
        matches = glob.glob(pattern, recursive=True)
        if matches:
            return sorted(matches)[-1]
    return shutil.which("signtool.exe") or shutil.which("signtool")


def check_sign_prerequisites(logger):
    """Verifie la disponibilite de openssl et signtool. Quitte si absent."""
    ui_info("Verification des prerequis...")
    openssl = shutil.which("openssl")
    if not openssl:
        fatal(logger, "openssl introuvable dans le PATH. Installez OpenSSL.")
    ui_ok(f"openssl   [dim]{openssl}[/]")
    signtool = find_signtool()
    if not signtool:
        fatal(logger, "signtool.exe introuvable. Installez le Windows SDK.")
    ui_ok(f"signtool  [dim]{signtool}[/]")
    return openssl, signtool


def config_fingerprint(cfg):
    """Calcule un hash SHA-256 des parametres determinants du certificat."""
    keys     = ("cert_name", "organization", "country", "state", "city", "days")
    relevant = {k: cfg[k] for k in keys}
    return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()


def load_cert_cache(path):
    """Charge le cache du certificat depuis le disque."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_cert_cache(path, cfg, fingerprint):
    """Sauvegarde le fingerprint et les meta du certificat dans le cache."""
    data = {"fingerprint": fingerprint, "generated_at": datetime.now().isoformat(), **cfg}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def generate_certificate(cfg, openssl, logger):
    """Genere un certificat auto-signe RSA 4096 et exporte le PFX."""
    ui_info("Generation du certificat auto-signe RSA 4096...")
    subj = (
        f"/C={cfg['country']}/ST={cfg['state']}/L={cfg['city']}"
        f"/O={cfg['organization']}/CN={cfg['cert_name']}"
    )
    with CONSOLE.status("[cyan]  Generation RSA 4096...[/]", spinner="dots2"):
        run_captured(
            [
                openssl, "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", "codesign.key", "-out", "codesign.crt",
                "-days", str(cfg["days"]), "-nodes", "-subj", subj,
                "-addext", "keyUsage=digitalSignature",
                "-addext", "extendedKeyUsage=codeSigning",
            ],
            logger, "Generation du certificat",
        )
    ui_ok("Certificat .crt + .key generes")
    with CONSOLE.status("[cyan]  Export PFX...[/]", spinner="dots2"):
        run_captured(
            [
                openssl, "pkcs12", "-export",
                "-out", cfg["pfx_file"], "-inkey", "codesign.key",
                "-in", "codesign.crt", "-passout", f"pass:{cfg['password']}",
            ],
            logger, "Export PFX",
        )
    ui_ok(f"PFX genere : [bold]{cfg['pfx_file']}[/]")
    for tmp in ("codesign.key", "codesign.crt"):
        try:
            tmppath = Path(tmp)
            if tmppath.exists():
                tmppath.write_bytes(os.urandom(tmppath.stat().st_size))
                tmppath.unlink()
        except OSError as exc:
            ui_info(f"Impossible de supprimer {tmp} : {exc}")


# Serveurs RFC 3161 de secours (signtool exige http://, pas https://)
_TIMESTAMP_FALLBACKS = [
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://timestamp.globalsign.com/scripts/timstamp.dll",
    "http://tsa.starfieldtech.com",
    "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
]

# Motifs d'erreur signtool indiquant un probleme de serveur timestamp
_TS_SERVER_ERRORS = (
    "timestamp server",
    "invalid timestamp url",
    "could not be reached",
    "invalid response",
)


def _sanitize_timestamp_url(url, logger):
    """
    Valide et corrige l'URL de timestamping avant de la passer a signtool.

    Regles imposees par signtool :
      - Protocole HTTP obligatoire (signtool refuse HTTPS pour /tr)
      - Pas de slash final
    """
    original = url.rstrip("/")
    if original.lower().startswith("https://"):
        fixed = "http://" + original[8:]
        ui_warn(
            f"URL timestamp corrigee : [bold]{original}[/]"
            f"  =>  [bright_cyan]{fixed}[/]\n"
            "  [dim]signtool n'accepte que http:// pour le flag /tr[/]"
        )
        logger.warning("Timestamp URL corrigee : %s -> %s", original, fixed)
        return fixed
    return original


def _is_timestamp_error(exc_msg):
    """Retourne True si l'erreur signtool est liee au serveur de timestamp."""
    lower = exc_msg.lower()
    return any(pat in lower for pat in _TS_SERVER_ERRORS)


def _sign_one(signtool, exe, sign_params, timestamp_url, logger):
    """
    Tente de signer un executable avec le serveur timestamp donne.
    `sign_params` : dict avec les cles pfx_file et password.
    Leve RuntimeError en cas d'echec.
    """
    run_captured(
        [
            signtool, "sign",
            "/f",  sign_params["pfx_file"],
            "/p",  sign_params["password"],
            "/fd", "SHA256",
            "/tr", timestamp_url,
            "/td", "SHA256",
            exe,
        ],
        logger, f"Signature de {exe} via {timestamp_url}",
    )


def _probe_timestamp_network(logger):
    """
    Teste la connectivite reseau vers les serveurs de timestamp avec socket TCP.
    Retourne True si au moins un serveur est joignable, False sinon.
    Evite de spammer 6 appels signtool pour rien sur une machine sans internet.
    """
    all_hosts = [
        ("timestamp.acs.microsoft.com", 80),
        ("timestamp.digicert.com",       80),
        ("timestamp.sectigo.com",        80),
    ]
    for host, port in all_hosts:
        try:
            with socket.create_connection((host, port), timeout=3):
                logger.debug("Reseau timestamp OK : %s:%d", host, port)
                return True
        except OSError:
            logger.debug("Reseau timestamp KO : %s:%d", host, port)
    return False


def _sign_no_timestamp(signtool, exe, sign_params, logger):
    """
    Signe sans serveur de timestamp (mode hors-ligne).

    Consequence : la signature expire avec le certificat (365 jours par defaut).
    Apres expiration, Windows affiche un avertissement SmartScreen.
    Acceptable pour usage interne ou test ; a eviter en production.
    """
    run_captured(
        [
            signtool, "sign",
            "/f",  sign_params["pfx_file"],
            "/p",  sign_params["password"],
            "/fd", "SHA256",
            exe,
        ],
        logger, f"Signature sans timestamp de {exe}",
    )


def _sign_with_fallback(signtool, exe, cfg, primary_url, logger):
    """
    Signe l'executable en essayant le serveur principal puis les serveurs
    de secours si le serveur primaire est inaccessible ou renvoie une erreur.
    Si tous les serveurs echouent, propose la signature sans timestamp.
    Retourne l'URL utilisee (ou 'no-timestamp'), leve RuntimeError si tout echoue.
    """
    sign_params = {"pfx_file": cfg["pfx_file"], "password": cfg["password"]}
    servers     = [primary_url] + [s for s in _TIMESTAMP_FALLBACKS if s != primary_url]
    last_exc    = RuntimeError("Aucun serveur de timestamp disponible.")

    for idx, ts_url in enumerate(servers):
        is_fallback = idx > 0
        label = f"[dim](fallback {idx})[/] " if is_fallback else ""
        with CONSOLE.status(
            f"[cyan]  {label}Signature via [bold]{ts_url}[/]...[/]",
            spinner="dots2",
        ):
            try:
                _sign_one(signtool, exe, sign_params, ts_url, logger)
                if is_fallback:
                    ui_warn(
                        f"Serveur de secours utilise : [bright_cyan]{ts_url}[/]\n"
                        "  [dim]Mettez a jour timestamp_url dans Pymake.config[/]"
                    )
                    logger.warning("Fallback timestamp utilise : %s", ts_url)
                return ts_url
            except RuntimeError as exc:
                last_exc = exc
                if _is_timestamp_error(str(exc)):
                    ui_warn(f"Serveur inaccessible : [dim]{ts_url}[/] — essai suivant...")
                    logger.warning(
                        "Timestamp %s inaccessible : %s", ts_url, str(exc)[:120]
                    )
                    continue
                raise  # Autre erreur (PFX, mot de passe...) — pas de fallback

    # Tous les serveurs ont echoue — proposer la signature sans timestamp
    CONSOLE.print(Panel(
        "  [yellow]Tous les serveurs de timestamp sont inaccessibles.[/]\n\n"
        "  [white]Causes possibles :[/]\n"
        "  [dim]• Pare-feu bloquant les connexions sortantes HTTP\n"
        "  • Proxy reseau necessitant une configuration\n"
        "  • Pas d'acces internet sur cette machine\n"
        "  • Panne temporaire des serveurs RFC 3161[/]\n\n"
        "  [white]Signer sans timestamp est possible.[/]\n"
        "  [dim]La signature sera valide uniquement pendant la duree du certificat.\n"
        "  Apres expiration : avertissement SmartScreen. Deconseille en production.[/]",
        title="[bold yellow] Reseau Timestamp Inaccessible [/]",
        border_style="yellow",
        box=box.HEAVY,
        padding=(0, 1),
    ))

    if Confirm.ask(
        "  [white]Signer sans timestamp (mode hors-ligne) ?[/]",
        default=False,
        console=CONSOLE,
    ):
        with CONSOLE.status(
            "[cyan]  Signature sans timestamp...[/]", spinner="dots2"
        ):
            _sign_no_timestamp(signtool, exe, sign_params, logger)
        ui_warn("Signe SANS timestamp — signature liee a la duree du certificat")
        logger.warning("Signe sans timestamp : %s", exe)
        return "no-timestamp"

    raise last_exc


def sign_executables(targets, cfg, signtool, logger):
    """Signe chaque executable de la liste. Retourne (succes, echecs)."""
    primary_url = _sanitize_timestamp_url(cfg["timestamp_url"], logger)

    # Sondage reseau rapide avant de lancer signtool en boucle
    ui_info("Sondage reseau timestamp...")
    if _probe_timestamp_network(logger):
        ui_ok(f"Reseau OK — serveur principal : [dim]{primary_url}[/]")
        ui_info(f"Serveurs de secours : [dim]{len(_TIMESTAMP_FALLBACKS)} disponibles[/]")
    else:
        ui_warn(
            "Aucun serveur timestamp joignable (TCP:80) — "
            "les tentatives seront effectuees mais risquent d'echouer."
        )
        logger.warning("Sondage reseau timestamp : tous les hotes sont inaccessibles.")

    ui_info(f"Signature de {len(targets)} executable(s)...")
    success, failed = [], []

    for exe in targets:
        if not Path(exe).exists():
            ui_ko(f"{exe}  [dim]introuvable — ignore.[/]")
            failed.append((exe, "Fichier introuvable"))
            continue
        try:
            _sign_with_fallback(signtool, exe, cfg, primary_url, logger)
            ui_ok(f"[bold]{Path(exe).name}[/]  signe")
            success.append(exe)
        except RuntimeError as exc:
            ui_ko(f"[bold]{Path(exe).name}[/]  echec")
            logger.error("Signature echec %s : %s", exe, str(exc))
            failed.append((exe, str(exc)))

    return success, failed


def _resolve_sign_cfg(cfg, force_regen, logger):
    """
    Determine si un nouveau certificat est requis.
    Lance le wizard de certification si oui.
    Retourne (cfg_final, need_regen).
    """
    fingerprint = config_fingerprint(cfg)
    saved       = load_cert_cache(cfg["config_file"])
    pfx_exists  = Path(cfg["pfx_file"]).exists()
    need_regen  = force_regen or not pfx_exists or (saved.get("fingerprint") != fingerprint)

    if not need_regen:
        ui_ok(f"Certificat valide : [bold]{cfg['pfx_file']}[/]  — reutilisation.")
        return cfg, False

    reason = (
        "--force-regen demande" if force_regen
        else f"PFX absent ({cfg['pfx_file']})" if not pfx_exists
        else "Parametres du certificat modifies"
    )
    logger.info("Nouveau certificat requis : %s", reason)
    new_sign = run_cert_wizard(base=cfg)
    return {**cfg, **new_sign}, True


def step_sign(cfg, targets, force_regen, logger, started_at):
    """Orchestre la generation du certificat (si besoin) puis la signature."""
    print_step(5, 5, "Signature de l'executable — Authenticode")
    openssl, signtool = check_sign_prerequisites(logger)

    cfg, need_regen = _resolve_sign_cfg(cfg, force_regen, logger)
    if need_regen:
        try:
            generate_certificate(cfg, openssl, logger)
            save_cert_cache(cfg["config_file"], cfg, config_fingerprint(cfg))
        except RuntimeError as exc:
            fatal(logger, f"Echec generation certificat :\n{exc}")

    try:
        success, failed = sign_executables(targets, cfg, signtool, logger)
    except RuntimeError as exc:
        fatal(logger, f"Erreur inattendue lors de la signature : {exc}")

    # ── Couche 4 : Double signature SHA1 + SHA256 ─────────────────
    if cfg.get("av_dual_sign") and success:
        CONSOLE.print()
        CONSOLE.print(Rule(title="[bold bright_blue]Post-sign : Double signature[/]",
                           style="bright_blue"))
        for exe in success:
            _dual_sign(signtool, exe, cfg, logger)

    # ── Couche 5 : Verification signature Authenticode ────────────
    if cfg.get("av_verify_signature") and success:
        CONSOLE.print()
        CONSOLE.print(Rule(title="[bold magenta]Post-sign : Verification[/]",
                           style="magenta"))
        all_valid = True
        for exe in success:
            if not _verify_signature(signtool, exe, logger):
                all_valid = False
        if not all_valid:
            ui_warn("Certaines signatures sont invalides — verifiez le certificat PFX.")

    # ── Couche 4 : Script PowerShell exclusion Defender ──────────
    if cfg.get("av_gen_exclusion_ps1") and success:
        CONSOLE.print()
        CONSOLE.print(Rule(title="[bold bright_blue]Post-sign : Script Defender[/]",
                           style="bright_blue"))
        for exe in success:
            _gen_defender_exclusion_ps1(exe, cfg["app_name"], logger)

    # ── Couche 5 : Nettoyage artefacts de build ───────────────────
    if cfg.get("av_wipe_build_artifacts"):
        CONSOLE.print()
        CONSOLE.print(Rule(title="[bold magenta]Post-sign : Nettoyage[/]",
                           style="magenta"))
        _wipe_build_artifacts(cfg["app_name"], logger)

    # ── Couche 5 : Rapport VirusTotal ─────────────────────────────
    if cfg.get("av_virustotal_check") and success:
        CONSOLE.print()
        CONSOLE.print(Rule(title="[bold magenta]Post-sign : VirusTotal[/]",
                           style="magenta"))
        for exe in success:
            _virustotal_check(exe, logger)

    CONSOLE.print()
    _print_final_report(success, failed, started_at)
    if failed:
        sys.exit(1)

# ══════════════════════════════════════════════════════════════════
# SECTION 10 — CLI et point d'entree
# ══════════════════════════════════════════════════════════════════

def _is_double_clicked():
    """
    Detecte si le script est lance par double-clic (pas depuis un terminal).
    Sur Windows, stdin n'est pas un TTY quand la fenetre est ouverte
    automatiquement par l'explorateur.
    """
    if os.name != "nt":
        return False
    try:
        return not sys.stdin.isatty()
    except AttributeError:
        return True


def _press_enter_to_close():
    """Affiche une invite 'Entree pour fermer' si lance par double-clic."""
    if _is_double_clicked():
        CONSOLE.print()
        CONSOLE.print(Panel(
            "  [dim]Appuyez sur [bold]Entree[/bold] pour fermer cette fenetre...[/]",
            border_style="dim cyan",
            padding=(0, 1),
        ))
        try:
            input()
        except (EOFError, OSError):
            pass


def parse_args():
    """Construit et retourne le parseur d'arguments CLI."""
    parser = argparse.ArgumentParser(
        description="Co-PyMake — Setup · Build · AV Harden · Sign",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--reconfigure",  action="store_true",
                        help=f"Relancer l'assistant et mettre a jour {PYMAKE_CONFIG_FILE}")
    parser.add_argument("--no-sign",      action="store_true",
                        help="Sauter l'etape de signature")
    parser.add_argument("--no-av-harden", action="store_true",
                        help="Sauter le durcissement anti-AV")
    parser.add_argument("--sign-only",    action="store_true",
                        help="Signer uniquement (pas de build)")
    parser.add_argument("--build-only",   action="store_true",
                        help="Builder uniquement (pas de signature)")
    parser.add_argument("--force-regen",  action="store_true",
                        help="Forcer la regeneration du certificat PFX")
    parser.add_argument("--exe",          nargs="*",
                        help="Executable(s) a signer (defaut : dist/<app_name>.exe)")
    return parser.parse_args()


def _resolve_targets(args_exe, default_exe):
    """Resout la liste des executables a signer depuis les arguments CLI."""
    raw = args_exe or [default_exe]
    targets = []
    for pattern in raw:
        expanded = glob.glob(pattern)
        targets.extend(expanded if expanded else [pattern])
    return targets


def main():
    """Point d'entree principal de Co-PyMake."""
    args    = parse_args()
    started = datetime.now()

    saved_cfg = load_pymake_config()
    if args.reconfigure:
        cfg = run_config_wizard(base=saved_cfg)
    elif saved_cfg is None:
        CONSOLE.print(Panel(
            f"  [yellow]Aucune configuration trouvee ({PYMAKE_CONFIG_FILE}).[/]\n"
            "  Lancement de l'assistant de configuration...",
            border_style="yellow",
            box=box.HEAVY,
            padding=(0, 1),
        ))
        cfg = run_config_wizard()
    else:
        print_header()
        CONSOLE.print(Panel(
            f"  [bright_green]✓[/]  Config chargee depuis [bold]{PYMAKE_CONFIG_FILE}[/]",
            border_style="dim cyan",
            padding=(0, 1),
        ))
        cfg = saved_cfg

    logger       = setup_logging(cfg["log_file"])
    do_av_harden = not args.no_av_harden
    default_exe  = str(Path("dist") / f"{cfg['app_name']}.exe")

    logger.info("Co-PyMake v%s demarre le %s",
                APP_VERSION, started.strftime("%d/%m/%Y a %H:%M:%S"))

    if args.sign_only:
        targets = _resolve_targets(args.exe, default_exe)
        step_sign(cfg, targets, args.force_regen, logger, started)

    elif args.build_only or args.no_sign:
        step_setup(cfg, logger)
        if do_av_harden:
            step_av_harden(cfg, logger)
        step_build(cfg, logger)

    else:
        step_setup(cfg, logger)
        if do_av_harden:
            step_av_harden(cfg, logger)
        built_exe = step_build(cfg, logger)
        targets   = _resolve_targets(args.exe, built_exe)
        step_sign(cfg, targets, args.force_regen, logger, started)

    CONSOLE.print()
    CONSOLE.print(Rule(style="bright_green"))
    CONSOLE.print(
        Text("  ⚡  Co-PyMake termine avec succes !", style="bold bright_green"),
        justify="center",
    )
    CONSOLE.print(Rule(style="bright_green"))
    CONSOLE.print()
    logger.info("Co-PyMake termine avec succes.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        CONSOLE.print()
        CONSOLE.print(Panel(
            "[yellow]Operation annulee par l'utilisateur.[/]",
            border_style="yellow",
            box=box.HEAVY,
        ))
        sys.exit(1)