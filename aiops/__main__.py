"""Entry point for all tools: `python -m aiops <tool> [args]`."""

import importlib
import sys

# tool name -> module exposing main(argv)
TOOLS = {
    "cve-watch": "aiops.agents.cve_watch.cli",
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in TOOLS:
        print("usage: python -m aiops <tool> [args]\n\ntools:\n" + "\n".join(f"  {t}" for t in TOOLS))
        return 2
    return importlib.import_module(TOOLS[sys.argv[1]]).main(sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
