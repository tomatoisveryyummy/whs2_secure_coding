from fastapi import FastAPI, HTTPException
from typing import List, Optional
import sqlite3
import bcrypt
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    conn=create_connection()
    create_tables(conn)
    if not get_user_by_username(conn,"admin"):
        register_admin(conn,"admin","admin","Admin User")
    yield
    conn.close()

app = FastAPI(lifespan=lifespan)

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

def create_connection(): 
    conn = sqlite3.connect('shopping_mall.db') 
    return conn

def create_tables(conn): 
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            full_name TEXT,
            address TEXT,
            payment_info TEXT
        )
    ''') 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            category TEXT,
            price REAL,
            thumbnail_url TEXT
        )
    ''') 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS purchased (
            id INTEGER PRIMARY KEY,
            username TEXT,
            address TEXT,
            payment_info TEXT,
            product_name TEXT,
            status TEXT
        )
    ''')
    conn.commit()

def add_user(conn, username, password, role, full_name, address, payment_info):
    hashed_password = hash_password(password)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password, role, full_name, address, payment_info) VALUES (?, ?, ?, ?, ?, ?)',
                   (username, hashed_password, role, full_name, address, payment_info))
    conn.commit()
    user = {"username": username, "role": role, "full_name": full_name, "address": address, "payment_info": payment_info}
    return {"message": "User created successfully!", "user": user}

def register_admin(conn, username, password, full_name):
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)',
                   (username, password, 'admin', full_name))
    conn.commit()
    user = {"username": username, "password": password, "role": 'admin', "full_name": full_name}
    return {"message": "Admin registered successfully!", "user": user} 

def authenticate_user(conn, username, password):
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    stored_hash = cursor.fetchone()
    
    if stored_hash and verify_password(password, stored_hash[0]):
        cursor.execute(f'SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        user_info = {"username": user[1], "password": user[2], "role": user[3], "full_name": user[4], "address": user[5], "payment_info": user[6]}
        return {"message": f"Welcome back, {username}!", "user": user_info}
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")

def get_all_products(conn): 
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products')
    products = cursor.fetchall() 
    return [{"name": product[1], "category": product[2], "price": product[3], "thumbnail_url": product[4]} for product in products]

def add_product(conn, name, category, price, thumbnail_url): 
    cursor = conn.cursor()
    cursor.execute('INSERT INTO products (name, category, price, thumbnail_url) VALUES (?, ?, ?, ?)', (name, category, price, thumbnail_url))
    conn.commit()
    return {"message": "Product added successfully!"} 

def update_user_info(conn, username, full_name, address, payment_info): 
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET full_name = ?, address = ?, payment_info = ? WHERE username = ?', (full_name, address, payment_info, username))
    conn.commit() 
    return {"message": "User information updated successfully!"} 

def get_user_by_username(conn, username):
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    return cursor.fetchone() 

def purchase_product(conn, username, address, payment_info, product_name):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO purchased (username, address, payment_info, product_name, status) VALUES(?, ?, ?, ?, ?)",
                    (username, address, payment_info, product_name, "Awaiting"))
    conn.commit()
    return {"message": f"Product purchased successfully!"}

def get_purchased_products(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM purchased")
    purchases = cursor.fetchall()
    return [{"id": purchase[0], "username": purchase[1], "address": purchase[2], "payment_info": purchase[3], 
             "product_name": purchase[4], "status": purchase[5]} for purchase in purchases]

def update_status(conn, id, status):
    cursor = conn.cursor()
    cursor.execute("UPDATE purchased SET status = ? WHERE id = ?", (status, id))
    conn.commit()
    return {"message": "Status updated successfully!"}

@app.post("/register")
async def register_user(username: str, password: str, role: str, full_name: str, address: Optional[str] = None, payment_info: Optional[str] = None):
    conn = create_connection()
    result = add_user(conn, username, password, role, full_name, address, payment_info)
    conn.close()
    return result

@app.post("/login") 
async def login(username: str, password: str): 
    conn = create_connection()
    result = authenticate_user(conn, username, password) 
    conn.close()
    return result

@app.get("/products", response_model=List[dict])
async def get_products():
    conn = create_connection()
    products = get_all_products(conn)
    conn.close()
    return products

@app.post("/add_product") 
async def add_new_product(name: str, category: str, price: float, thumbnail_url: str):
    conn = create_connection()
    result = add_product(conn, name, category, price, thumbnail_url)
    conn.close()
    return result

@app.put("/update_user_info")
async def update_user_info_endpoint(username: str, full_name: str, address: str, payment_info: str):
    conn = create_connection()
    result = update_user_info(conn, username, full_name, address, payment_info) 
    conn.close()
    return result

@app.get("/purchase_product")
async def purchase_product_endpoint(username: str, address: str, payment_info: str, product_name: str):
    conn = create_connection()
    result = purchase_product(conn, username, address, payment_info, product_name)
    conn.close()
    return result

@app.get("/purchase_history", response_model=List[dict])
async def get_purchase_history_endpoint():
    conn = create_connection()
    result = get_purchased_products(conn)
    conn.close()
    return result

@app.get("/update_status")
async def update_purchased_info_endpoint(id: int, status: str):
    conn = create_connection()
    result = update_status(conn, id, status)
    conn.close()
    return result