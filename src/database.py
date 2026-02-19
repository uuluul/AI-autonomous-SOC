import sqlite3
import json
import os
from datetime import datetime

# 資料庫存放在 data 目錄，確保 Docker volume 可以持久化
DB_PATH = "data/cti_tasks.db"

def init_db():
    """初始化資料庫"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # 建立任務表
    c.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            source_type TEXT,
            raw_content TEXT,
            analysis_json TEXT,
            confidence INTEGER,
            status TEXT DEFAULT 'PENDING',
            created_at TEXT,
            updated_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_task(filename, source_type, raw_content, analysis_json, confidence):
    """插入新任務"""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    
    c.execute('''
        INSERT INTO tasks (filename, source_type, raw_content, analysis_json, confidence, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)
    ''', (filename, source_type, raw_content, json.dumps(analysis_json), confidence, now, now))
    
    conn.commit()
    conn.close()
    return c.lastrowid

def get_pending_tasks():
    """取得所有待審核任務"""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM tasks WHERE status='PENDING' ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def update_task_status(task_id, status, new_analysis_json=None):
    """更新任務狀態 (Approve/Reject)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    
    if new_analysis_json:
        c.execute("UPDATE tasks SET status=?, updated_at=?, analysis_json=? WHERE id=?", 
                  (status, now, json.dumps(new_analysis_json), task_id))
    else:
        c.execute("UPDATE tasks SET status=?, updated_at=? WHERE id=?", 
                  (status, now, task_id))
    
    conn.commit()
    conn.close()