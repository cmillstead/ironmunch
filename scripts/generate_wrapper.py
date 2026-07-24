"""Generate the TypeScript MCP wrapper from contract/operations.json. Spec: SPEC_2 §4. Milestone: M4."""
import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate/check the MCP TS wrapper (SPEC_2 §4).")
    parser.add_argument("--check", action="store_true", help="Verify the committed wrapper matches the contract.")
    parser.parse_args()
    raise NotImplementedError("M4 — SPEC_2 §4")


if __name__ == "__main__":
    main()
