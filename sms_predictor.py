"""
sms_predictor.py — CLI tool to detect phishing in SMS messages.

Analyses SMS text for UPI/Aadhaar phishing signals including:
  - English urgency phrases and phishing keywords
  - Regional language detection (Hindi, Tamil, Telugu, Bengali)
  - URL presence (always suspicious in OTP-style SMSes)
  - Sender ID spoofing detection
  - OTP sharing requests
  - Account threat patterns

Usage:
    python sms_predictor.py --text "Your Aadhaar will be blocked. Click http://uidai-kyc.xyz"
    python sms_predictor.py --text "आपका खाता बंद हो जाएगा" --sender "VK-UIDAI"
    python sms_predictor.py --batch sms_samples.txt
    python sms_predictor.py --interactive
"""

import argparse
import csv
import sys
from pathlib import Path

from config import REPORTING_CHANNELS
from features.deeplink_features import analyse_upi_deeplink, extract_upi_links
from features.sms_features import analyse_sms
from features.whatsapp_features import analyse_whatsapp

# Risk level thresholds
RISK_LEVELS = {
    (0.00, 0.20): ("✅ CLEAN",      "No phishing signals detected."),
    (0.20, 0.40): ("⚠  LOW RISK",  "Some signals — could be legitimate or low-sophistication phishing."),
    (0.40, 0.65): ("🟠 MEDIUM",    "Multiple phishing signals — treat with caution."),
    (0.65, 0.85): ("🚨 HIGH RISK", "Strong phishing indicators — likely fraudulent."),
    (0.85, 1.01): ("☠  PHISHING",  "Almost certainly a phishing SMS — DO NOT click any links or share OTP."),
}


def risk_label(score: float) -> tuple[str, str]:
    for (low, high), (label, msg) in RISK_LEVELS.items():
        if low <= score < high:
            return label, msg
    return ("🚨 HIGH RISK", "High phishing probability.")


def print_result(text: str, sender: str, result: dict) -> None:
    score  = result["sms_risk_score"]
    label, description = risk_label(score)

    print()
    print(f"  {'─'*58}")
    print(f"  SMS:    {text[:70]}{'…' if len(text)>70 else ''}")
    if sender:
        print(f"  Sender: {sender}")
    print(f"  {'─'*58}")
    print(f"  {label}  (score: {score:.3f})")
    print(f"  {description}")
    print()
    print(f"  {'Feature':<32} {'Value':<10} Status")
    print(f"  {'─'*32} {'─'*10} {'─'*14}")

    display = {
        "sms_urgency_score":        ("Urgency phrases score",    result["sms_urgency_score"] > 0.1),
        "has_url_in_sms":           ("Contains URL",             result["has_url_in_sms"] == 1),
        "sender_id_spoofed":        ("Sender ID spoofed",        result["sender_id_spoofed"] == 1),
        "sms_phish_keyword_count":  ("Phish keyword count",      result["sms_phish_keyword_count"] >= 2),
        "sms_impersonates_brand":   ("Impersonates brand",       result["sms_impersonates_brand"] == 1),
        "sms_asks_for_otp":         ("Asks to share OTP",        result["sms_asks_for_otp"] == 1),
        "sms_threatens_account":    ("Threatens account",        result["sms_threatens_account"] == 1),
        "sms_hinglish_phish_score": ("Regional lang score",      result["sms_hinglish_phish_score"] > 0.05),
    }

    for key, (label_str, is_suspicious) in display.items():
        val = result[key]
        val_str = f"{val:.3f}" if isinstance(val, float) else str(val)
        status  = "⚠  suspicious" if is_suspicious else "✓"
        print(f"  {label_str:<32} {val_str:<10} {status}")
    print()


def analyse_batch(filepath: str) -> None:
    path = Path(filepath)
    if not path.exists():
        print(f"❌  File not found: {filepath}")
        sys.exit(1)

    lines = [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"📋  Batch SMS analysis: {len(lines)} messages\n")

    results = []
    for i, line in enumerate(lines, 1):
        # Support optional "sender|text" format
        parts  = line.split("|", 1)
        sender = parts[0].strip() if len(parts) == 2 else ""
        text   = parts[-1].strip()
        result = analyse_sms(text, sender)
        label, _ = risk_label(result["sms_risk_score"])
        print(f"  [{i:>3}] {label:<15} {text[:60]}{'…' if len(text)>60 else ''}")
        results.append({"text": text, "sender": sender, **result})

    # Summary
    phish = sum(1 for r in results if r["is_phishing_sms"])
    print(f"\n  Summary: {phish}/{len(results)} SMSes flagged as phishing.")

    # Save CSV
    out = filepath.replace(".txt", "_results.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"  Results saved → {out}")


def interactive_mode() -> None:
    print("\n🛡️  UPI & Aadhaar SMS Phishing Detector — Interactive Mode")
    print("   Type an SMS message and press Enter to analyse.")
    print("   Optionally prefix with 'sender|' (e.g. VK-UIDAI|Your Aadhaar...)")
    print("   Type 'exit' to quit.\n")

    while True:
        try:
            line = input("  SMS> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Goodbye.")
            break
        if not line or line.lower() == "exit":
            break
        parts  = line.split("|", 1)
        sender = parts[0].strip() if len(parts) == 2 else ""
        text   = parts[-1].strip()
        result = analyse_sms(text, sender)
        print_result(text, sender, result)


def print_generic(text: str, mode: str) -> None:
    """Print a WhatsApp-message or UPI-link verdict (flags + advice + where to report)."""
    if mode == "upi":
        links = extract_upi_links(text)
        result = analyse_upi_deeplink(links[0] if links else text)
        bad, score = result["is_suspicious_link"], result["risk_score"]
        title = f"UPI link — risk level: {result['risk_level'].upper()}"
    else:
        result = analyse_whatsapp(text)
        bad, score = result["is_phishing"], result["risk_score"]
        title = "WhatsApp message"
    print()
    verdict = '🚨 SCAM LIKELY' if bad else ('⚠  some warning signs' if score >= 0.2 and result['flags'] else '✅ no strong scam signals')
    print(f"  {verdict}  ({title}, score {score:.2f})")
    for f in result["flags"]:
        print(f"   ⚠  {f}")
    print(f"\n  {result['advice']}")
    if bad:
        print("\n  Report:")
        for c in REPORTING_CHANNELS:
            print(f"   • {c['name']} — {c['contact']}: {c['when']}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UPI & Aadhaar SMS Phishing Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sms_predictor.py --text "Your Aadhaar will be blocked. Click http://evil.xyz"
  python sms_predictor.py --text "Dear customer" --sender "VK-UIDAI"
  python sms_predictor.py --batch sms_samples.txt
  python sms_predictor.py --interactive
        """,
    )
    parser.add_argument("--text",        help="SMS text to analyse")
    parser.add_argument("--sender",      default="", help="SMS sender ID (optional)")
    parser.add_argument("--batch",       help="Text file with one SMS per line")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("--mode", choices=["sms", "whatsapp", "upi"], default="sms",
                        help="What --text is: an SMS (default), a WhatsApp message, or a upi:// link")
    args = parser.parse_args()

    if args.text and args.mode != "sms":
        print_generic(args.text, args.mode)
    elif args.interactive:
        interactive_mode()
    elif args.text:
        result = analyse_sms(args.text, args.sender)
        print_result(args.text, args.sender, result)
    elif args.batch:
        analyse_batch(args.batch)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
