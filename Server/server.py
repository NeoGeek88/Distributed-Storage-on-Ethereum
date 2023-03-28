import sys
import os
import time
import random
import hashlib
import socket
import requests
import threading
import base64
import uuid
import sqlite3
import asyncio
import aiohttp
from datetime import datetime
from flask import Flask, request
import json


chunk_db_path = "chunks.db"
log_db_path = "logs.db"
node_db_path = "nodes.db"
chunk_path = "./chunks"


def connect_to_db(db_path):
    return sqlite3.connect(db_path)


def connect_to_chunk_db():
    return connect_to_db(chunk_db_path)


def connect_to_log_db():
    return connect_to_db(log_db_path)


def connect_to_node_db():
    return connect_to_db(node_db_path)


def db_execute(conn, stmt, commit=True):
    conn.execute(stmt)
    if commit:
        conn.commit()
    return conn


def build_chunk_db(conn):
    return db_execute(conn, """
        CREATE TABLE IF NOT EXISTS chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chunkHash TEXT NOT NULL,
            chunkdata BLOB NOT NULL,
            createdAt DATETIME NOT NULL,
            verified BOOLEAN NOT NULL
        ) 
    """)


def build_node_db(conn):
    return db_execute(conn, """
        CREATE TABLE IF NOT EXISTS nodes (
            nodeid TEXT PRIMARY KEY,
            ipaddr TEXT NOT NULL,
            netaddr TEXT,
            port INTEGER NOT NULL,
            status TEXT NOT NULL,
            lastcheckTimestamp DATETIME NOT NULL,
            offlinecount INTEGER NOT NULL
        )
    """)


def build_log_db(conn):
    return db_execute(conn, """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            content TEXT NOT NULL,
            timestamp DATETIME NOT NULL
        ) 
    """)


def add_chunk(conn, chunk_hash, chunk_data):
    _bytes = base64.b64decode(chunk_data)
    conn.execute(
        "INSERT INTO chunks (chunkHash, chunkData, createdAt, verified) VALUES (?, ?, ?, ?)", (chunk_hash, _bytes, datetime.now(), False))
    conn.commit()

    return conn


def set_verify_chunk(conn, chunk_hash):
    conn.execute("""
        UPDATE chunks
        SET verified=1
        where chunkHash=?
    """, (chunk_hash, ))
    conn.commit()

    return conn

def remove_chunk(conn, chunk_hash):
    conn.execute(
        """
        DELETE FROM chunks WHERE chunkHash=?
        """,
        (chunk_hash, )
    )
    conn.commit()

    return conn


def get_chunks(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM chunks")
    rows = cursor.fetchall()
    cursor.close()

    return rows

def get_chunk(conn, chunk_hash):
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM chunks where chunkHash=? AND verified=1 LIMIT 1", (chunk_hash, )
    )

    chunk = cursor.fetchone()
    
    cursor.close()

    return chunk


# TYPE: UPLOAD, DOWNLOAD, CHECK, SYSTEM
def log(conn, content, type):
    conn.execute(
        "INSERT INTO logs (type, content, timestamp) VALUES (?, ?, ?)",
        (type, content, datetime.now(),)
    )

    conn.commit()

    return conn

def get_logs(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs")

    logs = cursor.fetchall()
    cursor.close()

    return logs



app = Flask(__name__)

@app.route("/chunk", methods=["POST"])
def save_chunk():
    body = request.json
    print(body)

    chunk_hash = body["chunkHash"]
    chunk_data = body["chunkData"]

    chunk_db_conn = connect_to_chunk_db()
    add_chunk(chunk_db_conn, chunk_hash, chunk_data).close()

    with open(os.path.join(chunk_path, chunk_hash), "wb") as f:
        f.write(base64.b64decode(chunk_data))

    log_db_conn = connect_to_log_db()

    log(
        log_db_conn,
        f"chunk {chunk_hash} is successfully uploaded",
        "UPLOAD"
    ).close()


    return f"chunk {chunk_hash} has been successfully uploaded", 200

@app.route("/chunk/<hash>", methods=["GET"])
def download_chunk(hash):
    chunk_db_conn = connect_to_chunk_db()
    chunk = get_chunk(chunk_db_conn, hash)
    chunk_db_conn.close()

    if chunk is None:
        log_db_conn = connect_to_log_db()
        log(
            log_db_conn,
            f"chunk {hash} does not exist or verified",
            "DOWNLOAD"
        )
        log_db_conn.close()
        return f"Chunk {hash} not found.", 404

    else:
        response = {
            "chunkHash": chunk[1],
            "chunkData": base64.b64encode(chunk[2]).decode()
        }                
        print(response)

        return response, 200

@app.route("/chunk/verify", methods=["GET"])
def verify_chunks():
    chunk_db_conn = connect_to_chunk_db()
    db_execute(chunk_db_conn, """
        UPDATE chunks
        SET verified=1
    """)
    chunk_db_conn.close()
    return "all chunks are verified", 200

@app.route("/health", methods=['GET'])
def health():
    timestamp = time.time()
    log_conn = connect_to_log_db()
    log(log_conn, "Health Check", "CHECK")
    log_conn.close()
    
    return str(timestamp), 200

@app.route("/")
def hello():
    return "hello, world!", 200


if __name__ == "__main__":
    #create dbs
    if not os.path.exists(os.path.join(os.getcwd(), chunk_db_path)):
        build_chunk_db(connect_to_chunk_db()).close()        
    if not os.path.exists(os.path.join(os.getcwd(), node_db_path)):
        build_node_db(connect_to_node_db()).close()        
    if not os.path.exists(os.path.join(os.getcwd(), log_db_path)):
        build_log_db(connect_to_log_db()).close()        

    if not os.path.isdir(os.path.join(os.getcwd(), chunk_path)):
        os.mkdir(os.path.join(os.getcwd(), chunk_path))

    app.run(port=3000, debug= True)
    


    
    
        