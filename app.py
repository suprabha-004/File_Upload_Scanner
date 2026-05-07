# Import modules
from flask import Flask, render_template, request
import os

from modules.hash_utils import generate_hash
from modules.file_checker import classify_extension
from modules.vt_api import check_virustotal
from modules.content_analyzer import content_analysis
from modules.risk_model import risk_score

import config


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER


# Initialize database
def init_db():
    import sqlite3

    conn = sqlite3.connect('database/db.sqlite3')
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            file_hash TEXT,
            extension_flag BOOLEAN,
            vt_malicious INTEGER,
            vt_suspicious INTEGER,
            content_flags TEXT,
            risk_level TEXT,
            score INTEGER,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()



# DATABASE FUNCTION
def save_to_db(data):
    import sqlite3
    try:
        conn = sqlite3.connect('database/db.sqlite3')
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scans 
            (filename, file_hash, extension_flag, vt_malicious, vt_suspicious, content_flags, risk_level, score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data['filename'],
            data['hash'],
            data['ext'],
            data['vt'].get('malicious', 0) if data['vt'] else 0,
            data['vt'].get('suspicious', 0) if data['vt'] else 0,
            str(data['content']),
            data['risk'],
            data['score']
        ))

        conn.commit()
        conn.close()

    except Exception as e:
        print("DB Error:", e)


# ROUTES
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file uploaded"

    file = request.files['file']

    if file.filename == '':
        return "No selected file"

    # Save file
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    ext_type = classify_extension(file.filename)


    try:
        # ANALYSIS PIPELINE
        file_hash = generate_hash(filepath)
        ext_flag = classify_extension(file.filename)
        vt_stats = check_virustotal(file_hash)
        content_flags = content_analysis(filepath)

        if file.filename.lower().endswith(".bat"):
            content_flags.append("Batch script detected ⚠️")

        # Risk scoring
        risk, score = risk_score(ext_flag, vt_stats, content_flags)
        if file.filename.lower().endswith(".bat"):
            risk = "High Risk"
            score = max(score, 70)

        # SAVE TO DATABASE
        save_to_db({
            'filename': file.filename,
            'hash': file_hash,
            'ext': ext_flag,
            'vt': vt_stats,
            'content': content_flags,
            'risk': risk,
            'score': score
        })

    except Exception as e:
        return f"Error during scanning: {str(e)}"

    # RENDER RESULT
    return render_template(
        'result.html',
        filename=file.filename,
        hash=file_hash,
        ext=ext_flag,
        vt=vt_stats,
        content=content_flags,
        risk=risk,
        score=score
    )


@app.route('/history')
def history():
    import sqlite3

    try:
        conn = sqlite3.connect('database/db.sqlite3')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans ORDER BY scan_time DESC")
        rows = cursor.fetchall()

        conn.close()

        return render_template('history.html', scans=rows)

    except Exception as e:
        return f"Error loading history: {str(e)}"


# RUN APP
if __name__ == '__main__':
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("database", exist_ok=True)

    init_db()   # THIS LINE IS IMPORTANT TO CREATE THE DATABASE AND TABLES BEFORE FIRST RUN
    
    app.run(debug=True)