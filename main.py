"""Command-line entry point for the SecureQR generator."""

import os
import urllib.parse

from qr_generator import generate_and_save_qr
from scanner import evaluate_heuristics, query_google_safe_browsing

DEFAULT_GOOGLE_API_KEY = "AIzaSyDT2srrwUmeJtkl0R8XXVf7PU6Iq_x8LXM"


def _get_api_key():
   """Return the configured, default, or interactively supplied API key."""
    env_key = os.getenv("SAFE_BROWSING_API_KEY")
    if env_key:
        return env_key

    print("\nGoogle Safe Browsing API Configuration:")
    print("  [1] Use default API key")
    print("  [2] Enter your own API key")
    print("  [3] Skip Safe Browsing lookup (heuristics only)")

    choice = input("Select an option (1/2/3) [default: 1]: ").strip()

    if choice == "2":
        custom_key = input("Enter your Google Safe Browsing API key: ").strip()
        return custom_key if custom_key else None
    elif choice == "3":
        return None

    # Default to option 1
    return DEFAULT_GOOGLE_API_KEY


def _get_url():
    """Read a URL and ensure it has a protocol."""
    raw_url = input("\nEnter target URL: ").strip()
    if raw_url and not urllib.parse.urlparse(raw_url).scheme:
        raw_url = "https://" + raw_url
    return raw_url


def _show_api_result(api_result):
    """Display API findings and report whether a threat was found."""
    if not api_result:
        return False
    source_note = " (from cache)" if api_result.get("from_cache") else ""
    if api_result["flagged"]:
        print(f"\n[CRITICAL THREAT]{source_note}")
        for threat in api_result["threats"]:
            print(f"  ❌ Google Safe Browsing Flag: {threat}")
        return True
    if api_result.get("error"):
        print(f"\n[!] Safe Browsing Error: {api_result['error']}")
    else:
        print(
            f"\n[✓] Google Safe Browsing: No listings found"
            f"{source_note}."
        )
    return False


def _show_heuristics(heuristics):
    """Display heuristic findings and report whether the score is risky."""
    if not heuristics["warnings"]:
        print("[✓] Local Heuristics: Clean structure.")
        return False
    print(f"\n[HEURISTIC WARNINGS] (Score: {heuristics['score']})")
    for warning in heuristics["warnings"]:
        print(f"  ⚠️  {warning}")
    return heuristics["score"] >= 3


def main():
    """Analyze a URL and generate its QR code."""
    print("=" * 60)
    print("      SecureQR — Security-First QR Code Generator")
    print("=" * 60)

    api_key = _get_api_key()

    raw_url = _get_url()
    if not raw_url:
        print("[!] Error: URL input cannot be empty.")
        return

    print("\n[*] Analyzing target...")
    heuristics = evaluate_heuristics(raw_url)
    api_result = None
    if api_key:
        api_result = query_google_safe_browsing(raw_url, api_key)

    # Output Security Report
    print("\n" + "=" * 25 + " ASSESSMENT " + "=" * 25)
    print(f"URL: {raw_url}")

    is_hazardous = _show_api_result(api_result)
    is_hazardous = _show_heuristics(heuristics) or is_hazardous

    print("=" * 62)

    # Guard prompt on risk detection
    if is_hazardous:
        confirm = input(
            "\n[WARNING] URL shows elevated risk markers. "
            "Generate anyway? (y/N): "
        ).lower()
        if confirm != "y":
            print("[-] Generation aborted.")
            return

    outfile = input("\nEnter output filename [secure_qr.png]: ").strip()
    if not outfile:
        outfile = "secure_qr.png"

    path = generate_and_save_qr(raw_url, outfile)
    print(f"\n[+] Success! QR code saved to:\n    {path}")


if __name__ == "__main__":
    main()
