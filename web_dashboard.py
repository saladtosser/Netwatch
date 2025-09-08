#!/usr/bin/env python3
"""
NetWatch v2 - Web Dashboard
Enterprise-grade web interface for the IDS system
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import os
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netwatch-v2-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global data storage
ALERTS_DATA = []
THREAT_STATS = {
    'total_alerts': 0,
    'critical_alerts': 0,
    'high_alerts': 0,
    'medium_alerts': 0,
    'low_alerts': 0,
    'threat_score': 0,
    'packets_analyzed': 0,
    'rules_loaded': 0
}

# Database setup
def init_database():
    """Initialize SQLite database for persistent storage"""
    conn = sqlite3.connect('netwatch.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            sid TEXT,
            msg TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            threat_score INTEGER,
            escalated BOOLEAN,
            packet_size INTEGER,
            rule_class TEXT,
            raw_data TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            domain TEXT,
            threat_type TEXT,
            confidence INTEGER,
            source TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def add_alert_to_db(alert_data):
    """Add alert to database"""
    conn = sqlite3.connect('netwatch.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO alerts (sid, msg, src_ip, dst_ip, src_port, dst_port, 
                          protocol, threat_score, escalated, packet_size, rule_class, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        alert_data.get('sid', ''),
        alert_data.get('msg', ''),
        alert_data.get('src', ''),
        alert_data.get('dst', ''),
        alert_data.get('sport', 0),
        alert_data.get('dport', 0),
        alert_data.get('proto', ''),
        alert_data.get('threat_score', 0),
        alert_data.get('escalated', False),
        alert_data.get('packet_size', 0),
        alert_data.get('rule_class', ''),
        json.dumps(alert_data)
    ))
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    return jsonify(THREAT_STATS)

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify(ALERTS_DATA[-limit:])

@app.route('/api/alerts/<int:alert_id>')
def get_alert_details(alert_id):
    """Get detailed alert information"""
    conn = sqlite3.connect('netwatch.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
    alert = cursor.fetchone()
    
    conn.close()
    
    if alert:
        return jsonify({
            'id': alert[0],
            'timestamp': alert[1],
            'sid': alert[2],
            'msg': alert[3],
            'src_ip': alert[4],
            'dst_ip': alert[5],
            'src_port': alert[6],
            'dst_port': alert[7],
            'protocol': alert[8],
            'threat_score': alert[9],
            'escalated': alert[10],
            'packet_size': alert[11],
            'rule_class': alert[12],
            'raw_data': json.loads(alert[13]) if alert[13] else {}
        })
    else:
        return jsonify({'error': 'Alert not found'}), 404

@app.route('/api/threat-intel')
def get_threat_intel():
    """Get threat intelligence data"""
    conn = sqlite3.connect('netwatch.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM threat_intel ORDER BY timestamp DESC LIMIT 100')
    threats = cursor.fetchall()
    
    conn.close()
    
    threat_data = []
    for threat in threats:
        threat_data.append({
            'id': threat[0],
            'timestamp': threat[1],
            'ip_address': threat[2],
            'domain': threat[3],
            'threat_type': threat[4],
            'confidence': threat[5],
            'source': threat[6]
        })
    
    return jsonify(threat_data)

@app.route('/api/network-topology')
def get_network_topology():
    """Get network topology data"""
    # This would integrate with network discovery tools
    return jsonify({
        'nodes': [
            {'id': '192.168.1.1', 'type': 'router', 'status': 'active'},
            {'id': '192.168.1.100', 'type': 'server', 'status': 'active'},
            {'id': '192.168.1.50', 'type': 'workstation', 'status': 'active'},
        ],
        'links': [
            {'source': '192.168.1.1', 'target': '192.168.1.100'},
            {'source': '192.168.1.1', 'target': '192.168.1.50'},
        ]
    })

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    emit('status', {'message': 'Connected to NetWatch v2'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

def update_stats():
    """Update threat statistics"""
    global THREAT_STATS
    
    # Read from database
    conn = sqlite3.connect('netwatch.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM alerts')
    THREAT_STATS['total_alerts'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM alerts WHERE threat_score > 100')
    THREAT_STATS['critical_alerts'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM alerts WHERE threat_score > 50 AND threat_score <= 100')
    THREAT_STATS['high_alerts'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM alerts WHERE threat_score > 20 AND threat_score <= 50')
    THREAT_STATS['medium_alerts'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM alerts WHERE threat_score <= 20')
    THREAT_STATS['low_alerts'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT AVG(threat_score) FROM alerts')
    avg_score = cursor.fetchone()[0]
    THREAT_STATS['threat_score'] = int(avg_score) if avg_score else 0
    
    conn.close()

def background_updates():
    """Background thread for real-time updates"""
    while True:
        update_stats()
        
        # Emit updates to connected clients
        socketio.emit('stats_update', THREAT_STATS)
        socketio.emit('alerts_update', ALERTS_DATA[-10:])  # Last 10 alerts
        
        time.sleep(5)  # Update every 5 seconds

if __name__ == '__main__':
    init_database()
    
    # Start background update thread
    update_thread = threading.Thread(target=background_updates, daemon=True)
    update_thread.start()
    
    print("🚀 Starting NetWatch v2 Web Dashboard...")
    print("📊 Dashboard available at: http://localhost:5000")
    print("🔒 Enterprise Security Console Ready")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
