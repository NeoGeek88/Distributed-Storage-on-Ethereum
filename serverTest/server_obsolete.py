import sys
import os
import time
import random
import hashlib
import socket
import requests
import threading
import base64
from datetime import datetime
from flask import Flask, request
import uuid
import sqlite3
import asyncio
import aiohttp

db_path = "chunks.db"
node_db_path = "nodes.db"
log_db_path = "log.db"
chunks_path = "chunks"



class ChunkDatabase:
    def __init__(self, db_path, chunks_path):
        self.db_path = db_path

        # build the database
        if os.path.exists(db_path):
            self.connect()
        else:
            self.__build_new_db()

        # create chunk directory
        self.chunks_path = chunks_path
        if os.path.isdir(chunks_path):
            pass
        else:
            os.mkdir(self.chunks_path)

    def connect(self):
        if self.conn:
            self.conn.close()

        self.conn = sqlite3.connect(self.db_path)

        return self.conn

    def disconnect(self):
        self.conn.close()

    def __build_new_db(self):
        db_path = self.db_path

        if len(db_path) == 0:
            raise Exception("please provide the database filename")

        conn = self.connect()

        conn.execute("""
                CREATE TABLE IF NOT EXISTS chunks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chunkHash TEXT NOT NULL,
                    chunkdata BLOB NOT NULL,
                    createdAt DATETIME NOT NULL,
                    verified BOOLEAN NOT NULL
                ) 
        """)

        return conn

    def sync_from_dir(self, dir):
        pass

    def sync_from_blockchain(self):
        pass

    def add_chunk(self, chunk_hash, chunk_data):
        _bytes = base64.b64decode(chunk_data)
        self.conn.execute(
            "INSERT INTO chunks (chunkHash, chunkData, createdAt, verified) VALUES (?, ?, ?)", (chunk_hash, _bytes, datetime.now(), False))
        self.conn.commit()

    def verify_chunk(self, chunk_hash):
        self.conn.execute("""
            UPDATE chunks
            SET verified = 1
            where chunkHash = ?
        """, (chunk_hash, ))
        self.conn.commit()

    def remove_chunk(self, chunk_hash):
        self.conn.execute(
            "DELETE FROM chunks where chunkHash=?", (chunk_hash, ))
        self.conn.commit()

    def get_chunks(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM chunks")
        rows = cursor.fetchall()

        cursor.close()
        return rows

    def get_chunk(self, chunk_hash):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM chunks where chunkHash=? AND verified=1 LIMIT 1", (chunk_hash, ))
        chunk = cursor.fetchone()

        cursor.close()
        return chunk

    def garbage_collect(self):
        valid_chunks = [row[1] for row in self.get_chunks()]

        count = 0

        for local_chunk in os.listdir(self.chunks_path):
            local_chunk_path = os.path.join(self.chunks_path, local_chunk)

            if local_chunk not in valid_chunks:
                os.remove(local_chunk_path)
                count += 1

        return count


class NodeDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
        
        # build database
        if os.path.exists(self.db_path):
            self.connect()
        else:
            self.__build_new_db()
    
    def connect(self):
        self.conn = sqlite3.connect(self.node_db_path)
    
    def __build_new_db(self):
        db_path = self.db_path

        if len(db_path) == 0:
            raise Exception("please provide the database filename")

        conn = self.connect()

        conn.execute("""
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

        return conn

    def update_node(self):
        pass

    # acquire node list from blockchain
    def sync_nodes(self):
        
        pass
    

class LogDatabase:
    def __init__(self, db_path):
        self.db_path = db_path

        if os.path.exists(self.db_path):
            self.connect()
        else:
            self.__build_new_db()
        
    def connect(self):
        self.conn = sqlite3.connect(self.db_path)

        return self.conn

    def __build_new_db(self):
        db_path = self.db_path

        if len(db_path) == 0:
            raise Exception("please provide the databse filename")
        
        conn = self.connect()

        conn.execute("""
            create table if not exists logs (
                id integer primary key autoincrement,
                type text,
                content text not null,
                timestamp datetime not null
            ) 
        """)

        return conn

    def log(self, content, type="UPLOAD"):
        self.conn.execute(
            "INSERT INTO logs (type, content, timestamp) VALUES (?, ?, ?)",
            (type, content, datetime.now(),)
        )

        self.conn.commit()
    
    def get_logs(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM logs")

        logs = cursor.fetchall()
        cursor.close()

        return logs

    # require to pass a function to handle the connection
    def query(self, handler):
        handler(self.conn)
    
chunkDatabase = ChunkDatabase(db_path, chunks_path)
logDatabase = LogDatabase(log_db_path)

app = Flask(__name__)
# background tasks actively fetch other nodes

app.config["CHUNK_DB"] = chunks_path
app.config["NODE_DB"] = node_db_path
app.config["LOG_DB"] = log_db_path

# actively check other nodes
def node_check(nodes):
    pass

def check_loop():
    pass

def register():
    pass

@app.route("/chunk", methods=['POST'])
def save_chunk():
    body = request.json
    chunk_hash = body[""]
    chunk_data = body["chunk"]

    with open(os.path.join(chunkDatabase.chunks_path, chunk_hash)) as f:
        f.write(base64.b64decode(chunk_data))
        chunkDatabase.add_chunk(chunk_hash, chunk_data)
    
    logDatabase.log(
        f"chunk {chunk_hash} is uploaded from #request_from, #metadata",
        "UPLOAD",
    )

    return f"chunk {chunk_hash} has been successfully uploaded.", 200



@app.route("/chunk/<hash>", methods=["GET"])
def get_chunk(hash):
    chunk = chunkDatabase.get_chunk(hash)

    if chunk is None:
        logDatabase.log(
            f"chunk {hash} requested by #metadata does not exist or verified",
            "DOWNLOAD",
        )
        return f"Chunk {hash} not found.", 404
    else:
        response = {
            "chunkHash": chunk[1],
            "chunkData": chunk[2]
        }

        return response, 200

@app.route("/health", methods=['POST'])
def health():
    print(request)
    #logDatabase.log(f"health check from #node", )
    return str(time.time()), 200 

@app.route("/")
def hello():
    return "hello, world", 200

if __name__ == "__main__":
    app.run(port=3000)

