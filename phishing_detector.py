import os
import re
import csv

# Load phishing keywords from file
def load_keywords(filename):
    with open(filename, 'r') as f:
        return [line.strip().lower() for line in f.readlines()]

# Scan email content and score based on patterns
def analyze_email(content, keywords):
    score = 0
    flags = []

    # Rule 1: Check for phishing keywords
    for keyword in keywords:
        if keyword in content.lower():
            score += 15
            flags.append(f"Keyword detected: {keyword}")

    # Rule 2: Suspicious URL patterns
    if re.search(r'https?:\/\/(bit\.ly|tinyurl\.com|[a-zA-Z0-9\-]{10,}\.[a-z]{2,})', content):
        score += 20
        flags.append("Suspicious URL pattern detected")

    # Rule 3: Attachment indicators
    if re.search(r'\.exe|\.bat|\.js|\.vbs', content):
        score += 25
        flags.append("Suspicious attachment type detected")

    return score, flags

# Read emails from a directory and run analysis
def process_emails(email_dir, keywords):
    results = []

    for filename in os.listdir(email_dir):
        if filename.endswith(".txt"):
            with open(os.path.join(email_dir, filename), 'r', encoding='utf-8') as f:
                content = f.read()

            score, flags = analyze_email(content, keywords)
            status = "Phishing" if score >= 50 else "Safe"

            results.append({
                "filename": filename,
                "score": score,
                "status": status,
                "reasons": "; ".join(flags)
            })

    return results

# Save results to CSV
def export_results(results, output_file='flagged_emails.csv'):
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['filename', 'score', 'status', 'reasons']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for result in results:
            writer.writerow(result)

if __name__ == "__main__":
    keywords = load_keywords('phishing_keywords.txt')
    email_results = process_emails('/home/kali/phishguard/sampleemails', keywords)
    export_results(email_results)

    for result in email_results:
        print(f"{result['filename']} - {result['status']} ({result['score']}): {result['reasons']}")

