from flask import *
import secrets
import sqlite3
import bcrypt

app=Flask(__name__)
app.config['SECRET_KEY']=secrets.token_hex(16)

def init_db():
    con=sqlite3.connect('users.db')
    cur=con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password BLOB NOT NULL
    )''')
    con.commit()
    con.close()
init_db()

@app.route('/')
def index():
    return render_template('register.html')

@app.route('/register',methods=['POST','GET'])
def register():
    if request.method=='POST':
        username=request.form['email']
        password=request.form['password']

        con=sqlite3.connect('users.db')
        cur=con.cursor()
        
        cur.execute('SELECT * FROM users WHERE username=?',(username,))
        existing_user=cur.fetchone()

        #check if user already registerd
        if existing_user:
            con.close()
            return "<script> alert('username is already taken, Please choose another..');window.location.href='/register';</script>"

        #hash the password using bcrypt
        hashed_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())

        
        cur.execute('INSERT INTO users(username,password) VALUES (?,?)',(username,hashed_password))
        con.commit()
        con.close()

        flash("Registration Successful please login")
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login',methods=['POST','GET'])
def login():
    if request.method=='POST':
        username=request.form['email']
        password=request.form['password']

        con=sqlite3.connect('users.db')
        cur=con.cursor()
        cur.execute('SELECT * FROM users WHERE username=?',(username,))
        user=cur.fetchone()
        con.close()

        if user and bcrypt.checkpw(password.encode('utf-8'),user[2]):
            session['user_id']=user[0]
            return "<script> alert('Login success'); window.location.href='/users';</script>"
        else:
            return "<script> alert('Invalid username and password..'); window.location.href='/login';</script>"

    return render_template('login.html')


@app.route('/users')
def users():
    if 'user_id' in session:
        con=sqlite3.connect('users.db')
        cur=con.cursor()
        cur.execute('SELECT * FROM users')
        users=cur.fetchall()
        con.close()

        return render_template('users.html',users=users)
    else:
        return redirect(url_for('login'))

if __name__=='__main__':
    app.run(debug=True)