dangerous_ext = ['.exe', '.bat', '.sh', '.ps1']
suspicious_ext = ['.js', '.vbs', '.txt']
document_ext = ['.pdf', '.docx', '.pptx']

def classify_extension(filename):
    filename = filename.lower()

    if any(filename.endswith(ext) for ext in dangerous_ext):
        return "high"
    elif any(filename.endswith(ext) for ext in suspicious_ext):
        return "medium"
    elif any(filename.endswith(ext) for ext in document_ext):
        return "low"
    else:
        return "unknown"