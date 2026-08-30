"""
config_loader.py — Centralised configuration for Ransomware Defense toolkit.

Every script that previously hard-coded CISO_ip / attacker_ip / port values
should instead do:

    from config_loader import load_config
    cfg = load_config()
    ciso_ip   = cfg["defender"]["ciso_ip"]
    ciso_port = cfg["defender"]["ciso_port"]
"""

import os
import sys
import yaml


_DEFAULT_SEARCH_PATHS = [
    # Alongside this file (repo root)
    os.path.join(os.path.dirname(__file__), "config", "config.yaml"),
    # User home
    os.path.expanduser("~/.config/ransomware-defense/config.yaml"),
    # System-wide (Linux/macOS)
    "/etc/ransomware-defense/config.yaml",
    # Windows system-wide
    r"C:\ProgramData\RansomwareDefense\config.yaml",
]


def load_config(config_path: str = None) -> dict:
    """
    Load and return the YAML configuration dictionary.

    Parameters
    ----------
    config_path : str, optional
        Explicit path to a config.yaml file.  If omitted the function
        searches the standard locations defined in _DEFAULT_SEARCH_PATHS.

    Raises
    ------
    FileNotFoundError
        If no config file is found in any of the standard locations.
    ValueError
        If the file is found but cannot be parsed as valid YAML.
    """
    if config_path is None:
        for path in _DEFAULT_SEARCH_PATHS:
            if os.path.isfile(path):
                config_path = path
                break
        else:
            msg = (
                "No config.yaml found.\n"
                "Copy config/config.yaml.example → config/config.yaml and "
                "set your CISO IP, port, and monitoring options.\n"
                "Searched:\n  " + "\n  ".join(_DEFAULT_SEARCH_PATHS)
            )
            raise FileNotFoundError(msg)

    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse {config_path}: {exc}") from exc

    _validate(cfg, config_path)
    return cfg


def _validate(cfg: dict, path: str) -> None:
    """Minimal sanity check so scripts fail early with a clear message."""
    required = [
        ("defender", "ciso_ip"),
        ("defender", "ciso_port"),
    ]
    for section, key in required:
        if not cfg.get(section, {}).get(key):
            raise ValueError(
                f"Missing required config value: {section}.{key} in {path}"
            )

    ip = cfg["defender"]["ciso_ip"]
    if ip in ("your_CISO_ip", "your_attacker_ip", "CISO_machine_IP", "attacker_ip"):
        raise ValueError(
            f"config.yaml still contains a placeholder IP ({ip!r}). "
            "Replace it with the real CISO machine IP address."
        )


if __name__ == "__main__":
    # Quick self-test: python config_loader.py [optional_path]
    path = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        c = load_config(path)
        print("Config loaded OK:")
        print(f"  CISO IP   : {c['defender']['ciso_ip']}")
        print(f"  CISO port : {c['defender']['ciso_port']}")
        print(f"  Interface : {c.get('monitoring', {}).get('network_interface', 'not set')}")
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
