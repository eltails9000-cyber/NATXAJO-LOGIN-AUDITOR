from importlib.metadata import PackageNotFoundError, version


def get_version() -> str:
    try:
        return version("natxajo-login-auditor")
    except PackageNotFoundError:
        return "0.1.0"


__all__ = ["get_version"]
