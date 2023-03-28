import sys, os, time, random, hashlib, socket, requests

from flask import Flask, request, send_file

import uuid

import base64

import sqlite3

db_path = "chunks.db"
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
        self.conn = sqlite3.connect(self.db_path)
        
        return self.conn
            
    def disconnect(self):
        self.conn.close()

    def __build_new_db(self):
        db_path = self.db_path

        if len(db_path) == 0:
            raise Exception("please provide the database filename")

        conn = self.connect()
        
        conn.execute("""CREATE TABLE IF NOT EXISTS chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chunkHash TEXT NOT NULL,
                chunkdata BLOB NOT NULL
                ) 
        """)

        return conn

    def sync_from_dir(self, dir):
        pass

    def sync_from_blockchain(self):
        pass

    def add_chunk(self, chunk_hash, chunk_data):
        _bytes = base64.b64decode(chunk_data)
        self.conn.execute("INSERT INTO chunks (chunkHash, chunkData) VALUES (?, ?)", (chunk_hash, _bytes))
        self.conn.commit()

    def remove_chunk(self, chunk_hash):
        self.conn.execute("DELETE FROM chunks where chunkHash=?", (chunk_hash, ))
        self.conn.commit()

    def get_chunks(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM chunks")
        rows = cursor.fetchall()

        cursor.close()
        return rows

    def get_chunk(self, chunk_hash):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM chunks where chunkHash=? LIMIT 1", (chunk_hash, ))
        chunk = cursor.fetchone()
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
            

    

if __name__ == "__main__":
    chunkDatabase = ChunkDatabase(db_path, chunks_path)
    
