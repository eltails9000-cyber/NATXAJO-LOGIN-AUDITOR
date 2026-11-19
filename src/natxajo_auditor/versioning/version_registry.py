from dataclasses import dataclass


@dataclass(frozen=True)
class VersionManifest:
    version: str
    channel: str
    compatible_kernel: str


INITIAL_VERSIONS: tuple[VersionManifest, ...] = (
    VersionManifest("0.1.0", "Development", "0.1.x"),
)


class VersionRegistry:
    def __init__(self) -> None:
        self._versions = {item.version: item for item in INITIAL_VERSIONS}

    def available(self) -> list[VersionManifest]:
        return sorted(self._versions.values(), key=lambda item: item.version)

    def get(self, version: str) -> VersionManifest | None:
        return self._versions.get(version)
