"""``python -m siemulator`` entrypoint — runs uvicorn against the app factory."""

from __future__ import annotations

import uvicorn

from siemulator.config import host, port


def main() -> None:
    uvicorn.run(
        "siemulator.app:create_app",
        factory=True,
        host=host(),
        port=port(),
        log_level="info",
    )


if __name__ == "__main__":
    main()
