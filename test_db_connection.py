import psycopg2

try:
    conn = psycopg2.connect("dbname='Star' user='postgres' host='localhost' password='shikucode'")
    print("Connected to the database successfully")
except Exception as e:
    print(f"Failed to connect to the database: {e}")
