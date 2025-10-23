"""Compatibility shim that launches the canonical Tech Toolbox UI."""

from pathlib import Path
import runpy


def main() -> None:
    root_script = Path(__file__).resolve().parents[1] / "tech_toolbox.py"
    if not root_script.exists():
        raise FileNotFoundError(f"Unable to locate main Tech Toolbox script at {root_script}")

    runpy.run_path(str(root_script), run_name="__main__")


if __name__ == "__main__":
    main()
