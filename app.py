# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime
from flask import request


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')

# Конфігурація для завантаження файлів
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Переконайтеся, що папка uploads існує
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Спочатку перевіряємо, чи існують таблиці
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='users' OR name='wishes')")
    existing_tables = c.fetchall()
    
    if ('users',) not in existing_tables:
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                profile_pic TEXT DEFAULT 'default.png'
            )
        ''')
    
    if ('wishes',) not in existing_tables:
        c.execute('''
            CREATE TABLE wishes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT NOT NULL,
                description TEXT,
                price REAL,
                image TEXT,
                product_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # Це дозволить звертатись до колонок по імені
    c = conn.cursor()
    
    # Отримуємо всі побажання з інформацією про користувачів
    c.execute('''
        SELECT 
            w.id,
            w.title,
            w.description,
            w.price,
            w.image,
            w.created_at,
            w.user_id,
            u.username,
            u.profile_pic as user_pic
        FROM wishes w
        JOIN users u ON w.user_id = u.id
        ORDER BY w.created_at DESC
    ''')
    
    wishes = [dict(row) for row in c.fetchall()]
    
    # Форматуємо дату для кожного побажання
    for wish in wishes:
        # Перетворюємо timestamp в читабельний формат
        created_at = datetime.strptime(wish['created_at'], '%Y-%m-%d %H:%M:%S')
        wish['created_at'] = created_at.strftime('%d.%m.%Y %H:%M')
    
    conn.close()
    return render_template('index.html', wishes=wishes, request=request)

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    
    if not query:
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Пошук користувачів
    c.execute('''
        SELECT id, username, profile_pic
        FROM users
        WHERE username LIKE ? OR email LIKE ?
        LIMIT 10
    ''', (f'%{query}%', f'%{query}%'))
    users = c.fetchall()
    
    # Пошук побажань
    c.execute('''
        SELECT 
            w.id,
            w.title,
            w.description,
            w.price,
            w.image,
            w.created_at,
            w.user_id,
            u.username,
            u.profile_pic as user_pic
        FROM wishes w
        JOIN users u ON w.user_id = u.id
        WHERE w.title LIKE ? OR w.description LIKE ?
        ORDER BY w.created_at DESC
        LIMIT 20
    ''', (f'%{query}%', f'%{query}%'))
    wishes = c.fetchall()
    
    conn.close()
    
    return render_template('search_results.html', 
                         query=query,
                         users=users,
                         wishes=wishes)

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute('SELECT id, username, profile_pic FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        flash('Користувача не знайдено')
        return redirect(url_for('index'))
    
    # Змінюємо запит, щоб отримати всі необхідні поля
    c.execute('''
        SELECT id, title, image, description, price 
        FROM wishes 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    ''', (user_id,))
    wishes = c.fetchall()
    conn.close()
    
    is_owner = 'user_id' in session and session['user_id'] == user_id
    return render_template('user_profile.html', user=user, wishes=wishes, is_owner=is_owner)

@app.route('/wish/<int:wish_id>')
def wish_detail(wish_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute('''
        SELECT w.*, u.username 
        FROM wishes w 
        JOIN users u ON w.user_id = u.id 
        WHERE w.id = ?
    ''', (wish_id,))
    wish = c.fetchone()
    conn.close()
    
    if not wish:
        flash('Побажання не знайдено')
        return redirect(url_for('index'))
    
    is_owner = 'user_id' in session and session['user_id'] == wish[1]
    return render_template('wish_detail.html', wish=wish, is_owner=is_owner)

@app.route('/add_wish', methods=['GET', 'POST'])
def add_wish():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = float(request.form.get('price', 0))  # Конвертуємо в float
        product_url = request.form.get('product_url')
        image = request.files['image']
        
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = 'default-wish.png'
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO wishes (user_id, title, description, price, image, product_url) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], title, description, price, filename, product_url))
        conn.commit()
        conn.close()
        
        return redirect(url_for('user_profile', user_id=session['user_id']))
    
    return render_template('add_wish.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Перевірка на пусті значення
        if not all([username, email, password, confirm_password]):
            flash('Всі поля повинні бути заповнені')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Паролі не співпадають')
            return render_template('register.html')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        try:
            c.execute('''INSERT INTO users 
                        (username, email, password, profile_pic) 
                        VALUES (?, ?, ?, ?)''',
                     (username, 
                      email, 
                      generate_password_hash(password),
                      'default.png'))
            conn.commit()
            flash('Реєстрація успішна!')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Користувач або email вже існують!')
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username', '')  # використовуємо get() для безпечного отримання даних
        password = request.form.get('password', '')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            # Перевіряємо, що user[0] не None перед використанням
            if user[0] is not None:
                return redirect(url_for('user_profile', user_id=user[0]))
            else:
                flash('Помилка при вході')
        else:
            flash('Неправильний email або пароль')
            
    return render_template('login.html')

@app.route('/update_profile_pic', methods=['POST'])
def update_profile_pic():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if 'profile_pic' not in request.files:
        flash('Не вибрано файл')
        return redirect(url_for('user_profile', user_id=session['user_id']))
    
    profile_pic = request.files['profile_pic']
    
    if profile_pic.filename == '':
        flash('Не вибрано файл')
        return redirect(url_for('user_profile', user_id=session['user_id']))
    
    if profile_pic and allowed_file(profile_pic.filename):
        try:
            # Створюємо унікальне ім'я файлу
            filename = secure_filename(f"{session['user_id']}_{profile_pic.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Зберігаємо новий файл
            profile_pic.save(filepath)
            
            # Оновлюємо базу даних
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            
            # Отримуємо старе фото
            c.execute('SELECT profile_pic FROM users WHERE id = ?', (session['user_id'],))
            old_pic = c.fetchone()[0]
            
            # Оновлюємо на нове фото
            c.execute('UPDATE users SET profile_pic = ? WHERE id = ?',
                     (filename, session['user_id']))
            conn.commit()
            conn.close()
            
            # Видаляємо старе фото, якщо воно не дефолтне
            if old_pic != 'default.png':
                try:
                    old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], old_pic)
                    if os.path.exists(old_filepath):
                        os.remove(old_filepath)
                except:
                    pass  # Ігноруємо помилки при видаленні старого файлу
            
            flash('Фото профілю оновлено')
        except Exception as e:
            flash('Помилка при оновленні фото')
            print(e)  # Для відладки
    else:
        flash('Дозволені тільки файли з розширенням: ' + ', '.join(ALLOWED_EXTENSIONS))
    
    return redirect(url_for('user_profile', user_id=session['user_id']))

@app.route('/wish/<int:wish_id>/delete', methods=['POST'])
def delete_wish(wish_id):
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}, 401
        
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    try:
        # Перевіряємо чи є користувач власником побажання
        c.execute('SELECT user_id, image FROM wishes WHERE id = ?', (wish_id,))
        wish = c.fetchone()
        
        if not wish:
            conn.close()
            return {'error': 'Wish not found'}, 404
            
        if wish[0] != session['user_id']:
            conn.close()
            return {'error': 'Unauthorized'}, 401
        
        # Видаляємо файл зображення, якщо він не є дефолтним
        if wish[1] != 'default-wish.png':
            try:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], wish[1])
                if os.path.exists(image_path):
                    os.remove(image_path)
            except Exception as e:
                print(f"Error deleting image: {e}")
        
        # Видаляємо побажання з бази даних
        c.execute('DELETE FROM wishes WHERE id = ?', (wish_id,))
        conn.commit()
        
        return {'success': True}, 200
        
    except Exception as e:
        print(f"Error deleting wish: {e}")
        return {'error': 'Server error'}, 500
        
    finally:
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)