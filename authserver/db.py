from flask import current_app
import psycopg2
from psycopg2.extras import DictCursor
import logging
from authserver.exceptions import AppError
from contextlib import contextmanager

def connect_db():
    try:
        conn = psycopg2.connect(dbname=current_app.config['DB_NAME'],
                                user=current_app.config['DB_USER'],
                                password=current_app.config['DB_PASSWORD'],
                                host=current_app.config['DB_HOST'],
                                port=current_app.config['DB_PORT'])
    except psycopg2.errors.OperationalError as err:
        logging.critical("failed to connect to the database; check connection params and server availability")
        raise Exception("failed to connect to database") from err
    else:
        return conn

@contextmanager
def connect_db(context_msg=None): 
    try:
        conn = psycopg2.connect(dbname=current_app.config['DB_NAME'],
                                            user=current_app.config['DB_USER'],
                                            password=current_app.config['DB_PASSWORD'],
                                            host=current_app.config['DB_HOST'],
                                            port=current_app.config['DB_PORT'])
        yield conn
        conn.commit()
    except psycopg2.Error as e: 
        print(f"Exiting DB connection context with postgres error SQLSTATE code: {e.pgcode}. Any transactions may be rolled back. {context_msg=}")
        conn.rollback()
        raise AppError(description="Database error")
    except Exception:
        print(f"Exiting DB connection context with error. Any transactions may be rolled back. {context_msg=}")
        conn.rollback()
        raise AppError(description="Database error")
    finally: 
        conn.close()
        
def find_account_by_username(username: str) -> dict: 
    with connect_db("searching user account records by username") as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor: 
            query = """
                SELECT username, pgp_sym_decrypt(secret, %s) AS password, projects, authorize_clients, is_admin, approved_aud 
                FROM user_accounts WHERE username = %s
            """
            cursor.execute(query, (current_app.config['DB_ENCRYPTION_PASSWORD'], username))
            return cursor.fetchone()


def add_refresh_token(username, token, client_id):
    with connect_db("adding refresh token to db") as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor: 
            query = "INSERT INTO refresh_tokens ( username, refresh_token, used, client_id ) values (%s, %s, FALSE, %s) RETURNING *;"
            cursor.execute(query, (username, token, client_id))
            result = cursor.fetchone()
             
def get_refresh_token(token):
    with connect_db("getting refresh token record from db") as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor: 
            query = "SELECT * FROM refresh_tokens WHERE refresh_token = %s;"
            cursor.execute(query, (token,))
            return cursor.fetchone()

def update_used_refresh_token(token):
    with connect_db("updating used refreshe token in db") as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor: 
            query = "UPDATE refresh_tokens SET used=TRUE where refresh_token=%s RETURNING *;"
            cursor.execute(query, (token,))
            return cursor.fetchone()
        
def update_revoked_refresh_token(token):
    with connect_db("updating revoked refresh token in db") as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor: 
            query = "UPDATE refresh_tokens SET revoked=TRUE where refresh_token=%s RETURNING *;"
            cursor.execute(query, (token,))
            return cursor.fetchone()
 
