"""Human command entry point with import-only scaffold compatibility."""

from src.cli import main as cli_main


def main() -> int:
    """Preserve the initial import-only skeleton probe."""
    print("governed-agent-memory: scaffold only")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli_main())
