from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import threading
from crawler import main_crawler

app = Flask(__name__)
DATABASE = 'database.db'

def init_db():
    with sqlite3.connect(DATABASE) as connection:
        connection.execute('''CREATE TABLE IF NOT EXISTS Results (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            status TEXT,
            status_code INTEGER,
            subdomains TEXT,
            ip TEXT,
            ports TEXT,
            emails TEXT,
            phone_numbers TEXT,
            whois_info TEXT,
            wappalyzer_results TEXT,
            screenshot_path TEXT
        )''')

def insert_result(data):
    with sqlite3.connect(DATABASE) as insert:
        insert.execute('''
            INSERT INTO Results (url, title, status, status_code, subdomains, ip, ports, emails, phone_numbers, whois_info, wappalyzer_results, screenshot_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['url'], data['title'], data['status'], data['status_code'], '\n'.join(data['subdomains']), data['ip'],
            '\n'.join(data['ports']), '\n'.join(data['emails']), '\n'.join(data['phone_numbers']), str(data['whois_info']),
            str(data['wappalyzer_results']), data['screenshot_path']
        ))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/crawl', methods=['POST'])
def crawl():
    urls = request.form.getlist('urls')
    if len(urls) != 2:
        return redirect(url_for('index'))

    threading.Thread(target=perform_crawl, args=(urls,)).start()
    return redirect(url_for('result'))

def perform_crawl(urls):
    results = main_crawler(urls)
    for result in results:
        if result:
            insert_result(result)

@app.route('/result')
def result():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute('SELECT * FROM Results')
        data = cursor.fetchall()
    return render_template('result.html', data=data)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
