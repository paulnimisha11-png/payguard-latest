"""PayGuard. Importing the package loads a local `.env` (if there is one) before any module reads its settings."""
import os


def load_env(path: str | None = None) -> list[str]:
    """Reads KEY=value lines from `.env` next to the project into os.environ and returns the names it set.
    Variables that are already set win (so Render's dashboard, Docker and the shell always take precedence).
    A PEM pasted over several lines (-----BEGIN … -----END) is read as one value. Values are never printed.
    PAYGUARD_ENV_FILE picks another file; set it to an empty string to load nothing (the tests do)."""
    if path is None:
        path = os.environ.get("PAYGUARD_ENV_FILE", os.path.join(os.path.dirname(__file__), "..", ".env"))
    if not path or not os.path.isfile(path):
        return []
    found: dict[str, str] = {}
    key = None                                        # set while inside a multi-line PEM value
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if key:
                found[key] += "\n" + line.strip("\"'")
                if line.strip("\"'").startswith("-----END"):
                    key = None
                continue
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.removeprefix("export ").split("=", 1)
            name, value = name.strip(), value.strip()
            if not name.replace("_", "").isalnum():
                continue
            if value.lstrip("\"'").startswith("-----BEGIN") and "-----END" not in value:
                key = name
            found[name] = value.strip("\"'") if key else (
                value[1:-1] if len(value) > 1 and value[0] == value[-1] and value[0] in "\"'" else value)
    new = [k for k in found if k not in os.environ]
    os.environ.update({k: found[k] for k in new})
    return new


load_env()
