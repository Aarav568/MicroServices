import datetime
import os
from flask import Flask, request
import mysql.connector
from mysql.connector import errorcode

config = {
    'user': 'auth_user',
    'password': 'auth123',
    'host': 'localhost',
    'database': 'auth'
}

try:
    cnx = mysql.connector.connect(**config)
except mysql.connector.Error as err:
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
        print("Something is wrong with your user name or password")
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
        print("Database does not exist")
    else:
        print(err)
else:
    cursor = cnx.cursor()
    cursor.execute("SELECT * FROM user;")

    print(cursor.fetchone())
