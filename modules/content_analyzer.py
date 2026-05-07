import re

def content_analysis(filepath):
    patterns = [
        r'cmd.exe',
        r'powershell',
        r'curl ',
        r'wget ',
        r'del ',
        r'\brm\b',
        r'net user',
        r'eval\('
    ]

    findings = []

    with open(filepath, 'rb') as f:
        content = f.read().decode(errors='ignore')

        for pattern in patterns:
            if re.search(pattern, content):
                findings.append(pattern)

    return findings