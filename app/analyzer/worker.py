"""Entry point for the APK analysis worker process.

Kept tiny on purpose: a "spawn" worker imports only this module and the analyzer, not the web server, the OCR engine
or the database, so each APK scan process starts small and its memory is freed when it exits."""


def analyze_in_worker(path: str, name: str, workdir: str) -> dict:
    from .core import analyze_apk
    return analyze_apk(path, name, workdir=workdir)
