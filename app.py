from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import collections
import json
import sqlite3
import hashlib
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = '123456789' 
DATABASE = 'database.sqlite'

# Load censorship data
# WARNING! The censorship.dat file contains disturbing language when decrypted. 
# If you want to test whether moderation works, 
# you can trigger censorship using these words: 
# tier1badword, tier2badword, tier3badword
ENCRYPTED_FILE_PATH = 'censorship.dat'
fernet = Fernet('xpplx11wZUibz0E8tV8Z9mf-wwggzSrc21uQ17Qq2gg=')
with open(ENCRYPTED_FILE_PATH, 'rb') as encrypted_file:
    encrypted_data = encrypted_file.read()
decrypted_data = fernet.decrypt(encrypted_data)
MODERATION_CONFIG = json.loads(decrypted_data)
TIER1_WORDS = MODERATION_CONFIG['categories']['tier1_severe_violations']['words']
TIER2_PHRASES = MODERATION_CONFIG['categories']['tier2_spam_scams']['phrases']
TIER3_WORDS = MODERATION_CONFIG['categories']['tier3_mild_profanity']['words']

def get_db():
    """
    Connect to the application's configured database. The connection
    is unique for each request and will be reused if this is called
    again.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)

    if db is not None:
        db.close()


def query_db(query, args=(), one=False, commit=False):
    """
    Queries the database and returns a list of dictionaries, a single
    dictionary, or None. Also handles write operations.
    """
    db = get_db()
    
    try:
        with db:
            cur = db.execute(query, args)
        
        if not commit:
            rv = cur.fetchall()
            return (rv[0] if rv else None) if one else rv
        
        return cur

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

def get_user_activity(user_id):
    """Calculates user post count, community average, and sets a challenge target."""
    if not user_id:
        return None

    user_posts_row = query_db('SELECT COUNT(*) as count FROM posts WHERE user_id = ?', (user_id,), one=True)
    user_posts = user_posts_row['count'] if user_posts_row else 0

    avg_posts_row = query_db('''
        SELECT CAST(COUNT(posts.id) AS FLOAT) / MAX(1, (SELECT COUNT(*) FROM users)) as avg_count
        FROM posts
    ''', one=True)
    avg_posts = round(avg_posts_row['avg_count'] if avg_posts_row else 0.0, 1)

    suggested_target = max(user_posts + 5, int(avg_posts) + 5)

    return {
        'user_posts': user_posts,
        'avg_posts': avg_posts,
        'suggested_target': suggested_target
    }

@app.template_filter('datetimeformat')
def datetimeformat(value):
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
    else:
        return "N/A"
    return dt.strftime('%b %d, %Y %H:%M')

REACTION_EMOJIS = {
    'like': '❤️', 'love': '😍', 'laugh': '😂',
    'wow': '😮', 'sad': '😢', 'angry': '😠',
}
REACTION_TYPES = list(REACTION_EMOJIS.keys())

def init_groups():
    """Ensure groups and group_members tables exist, add group_id to posts, and seed default groups."""
    query_db('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT NOT NULL
        )
    ''')
    query_db('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Safely ensure posts table has group_id column
    try:
        query_db('ALTER TABLE posts ADD COLUMN group_id INTEGER REFERENCES groups(id)')
    except Exception:
        pass  # Column already exists

    # Seed initial named subgroups if table is empty
    existing_groups = query_db('SELECT COUNT(*) as count FROM groups', one=True)
    if existing_groups and existing_groups['count'] == 0:
        default_groups = [
            ('💻 Tech & Code', 'A subgroup for developers, tech enthusiasts, and builders.'),
            ('📚 Book Club', 'Discussing great reads, recommendations, and literary ideas.'),
            ('🏃 Fitness & Health', 'Sharing workout routines, healthy habits, and wellness tips.'),
            ('🎨 Creative Arts', 'A space for art, photography, design, and creative projects.')
        ]   
        for name, desc in default_groups:
            query_db('INSERT INTO groups (name, description) VALUES (?, ?)', (name, desc))

    # =========================================================
    # Design Claim 2: Seed Quarantine Subgroup (Group 999)
    # =========================================================
    query_db("INSERT OR IGNORE INTO groups (id, name, description) VALUES (999, '⚠️ Quarantine / Under Review', 'Posts with flagged content redirected for moderation review.')")


@app.route('/')
def feed():
    # Initialize subgroup database schema before executing feed queries
    init_groups()

    #  1. Get Pagination and Filter Parameters 
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    sort = request.args.get('sort', 'new').lower()
    show = request.args.get('show', 'all').lower()

    # Subgroup filter parameter
    selected_group_id = request.args.get('group_id', type=int)
    
    # Define how many posts to show per page
    POSTS_PER_PAGE = 10
    offset = (page - 1) * POSTS_PER_PAGE

    current_user_id = session.get('user_id')
    params = []

    #  2. Build Query with Subgroup Filtering & Quarantine Exclusion (Design Claim 2)
    if selected_group_id:
        where_clause = "WHERE p.group_id = ?"
        params.append(selected_group_id)
    else:
        # Exclude Quarantine posts (group_id = 999) unless explicitly viewing Group 999
        where_conditions = ["(p.group_id != 999 OR p.group_id IS NULL)"]

        if show == 'following' and current_user_id:
            where_conditions.append("p.user_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)")
            params.append(current_user_id)
        elif show == 'my_groups' and current_user_id:
            where_conditions.append("p.group_id IN (SELECT group_id FROM group_members WHERE user_id = ?)")
            params.append(current_user_id)

        where_clause = "WHERE " + " AND ".join(where_conditions)

    pagination_params = (POSTS_PER_PAGE, offset)

    if sort == 'popular':
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id,
                   g.id as group_id, g.name as group_name,
                   IFNULL(r.total_reactions, 0) as total_reactions
            FROM posts p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN groups g ON p.group_id = g.id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as total_reactions FROM reactions GROUP BY post_id
            ) r ON p.id = r.post_id
            {where_clause}
            ORDER BY total_reactions DESC, p.created_at DESC
            LIMIT ? OFFSET ?
        """
        final_params = params + list(pagination_params)
        posts = query_db(query, final_params) or []
    elif sort == 'recommended':
        posts = recommend(current_user_id, show == 'following' and current_user_id) or []
    else:  # Default sort is 'new'
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id,
                   g.id as group_id, g.name as group_name
            FROM posts p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN groups g ON p.group_id = g.id
            {where_clause}
            ORDER BY p.created_at DESC
            LIMIT ? OFFSET ?
        """
        final_params = params + list(pagination_params)
        posts = query_db(query, final_params) or []

    posts_data = []
    for post in posts:
        followed_poster = False
        if current_user_id and post['user_id'] != current_user_id:
            follow_check = query_db(
                'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
                (current_user_id, post['user_id']),
                one=True
            )
            if follow_check:
                followed_poster = True

        user_reaction = None
        if current_user_id:
            reaction_check = query_db(
                'SELECT reaction_type FROM reactions WHERE user_id = ? AND post_id = ?',
                (current_user_id, post['id']),
                one=True
            )
            if reaction_check:
                user_reaction = reaction_check['reaction_type']

        reactions = query_db('SELECT reaction_type, COUNT(*) as count FROM reactions WHERE post_id = ? GROUP BY reaction_type', (post['id'],)) or []
        comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post['id'],)) or []
        post_dict = dict(post)
        post_dict['content'], _ = moderate_content(post_dict['content'])
        comments_moderated = []
        for comment in comments_raw:
            comment_dict = dict(comment)
            comment_dict['content'], _ = moderate_content(comment_dict['content'])
            comments_moderated.append(comment_dict)
        posts_data.append({
            'post': post_dict,
            'reactions': reactions,
            'user_reaction': user_reaction,
            'followed_poster': followed_poster,
            'comments': comments_moderated
        })

    activity = get_user_activity(current_user_id) if current_user_id else None

    needed_contributions = []
    if current_user_id:
        needed_contributions = query_db('''
            SELECT p.id, u.username
            FROM posts p
            JOIN users u ON p.user_id = u.id
            JOIN follows f ON p.user_id = f.followed_id
            WHERE p.id NOT IN (SELECT post_id FROM comments)
            AND f.follower_id = ?
            ORDER BY p.created_at DESC
            LIMIT 3
        ''', (current_user_id,)) or []

    if current_user_id:
        all_groups = query_db('''
            SELECT g.id, g.name, g.description,
                   COUNT(gm.user_id) as member_count,
                   MAX(CASE WHEN gm.user_id = ? THEN 1 ELSE 0 END) as is_member
            FROM groups g
            LEFT JOIN group_members gm ON g.id = gm.group_id
            GROUP BY g.id
        ''', (current_user_id,)) or []
    else:
        all_groups = query_db('''
            SELECT g.id, g.name, g.description,
                   COUNT(gm.user_id) as member_count,
                   0 as is_member
            FROM groups g
            LEFT JOIN group_members gm ON g.id = gm.group_id
            GROUP BY g.id
        ''') or []

    return render_template('feed.html.j2', 
                           posts=posts_data, 
                           current_sort=sort,
                           current_show=show,
                           page=page,
                           per_page=POSTS_PER_PAGE,
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES,
                           activity=activity,
                           needed_contributions=needed_contributions,
                           all_groups=all_groups)

@app.route('/posts/new', methods=['POST'])
def add_post():
    """Handles creating a new post from the feed or a subgroup."""
    user_id = session.get('user_id')

    if not user_id:
        flash('You must be logged in to create a post.', 'danger')
        return redirect(url_for('login'))

    content = request.form.get('content')
    group_id_raw = request.form.get('group_id')
    group_id = int(group_id_raw) if group_id_raw and group_id_raw.isdigit() else None

    # Prevent manual selection of group 999
    if group_id == 999:
        group_id = None

    # Run moderation check to determine risk score and group redirection
    moderated_content, score = moderate_content(content)

    # Design Claim 2: Redirect high-risk posts (score >= 5.0) to Quarantine
    QUARANTINE_GROUP_ID = 999
    if score >= 5.0:
        group_id = QUARANTINE_GROUP_ID
        flash('Notice: Your post contained flagged content and was redirected to the Quarantine section for review.', 'warning')

    if content and content.strip():
        db = get_db()
        # Save the original RAW 'content' so moderation can evaluate it on read/analysis
        db.execute('INSERT INTO posts (user_id, content, group_id) VALUES (?, ?, ?)',
                   (user_id, content, group_id))
        db.commit()
        if score < 5.0:
            flash('Your post was successfully created!', 'success')
    else:
        flash('Post cannot be empty or was fully censored.', 'warning')

    return redirect(request.referrer or url_for('feed'))

@app.route('/groups/<int:group_id>')
def group_detail(group_id):
    """Displays a single subgroup with its description, members, and group-specific posts."""
    current_user_id = session.get('user_id')

    group = query_db('''
        SELECT g.id, g.name, g.description,
               COUNT(gm.user_id) as member_count,
               MAX(CASE WHEN gm.user_id = ? THEN 1 ELSE 0 END) as is_member
        FROM groups g
        LEFT JOIN group_members gm ON g.id = gm.group_id
        WHERE g.id = ?
        GROUP BY g.id
    ''', (current_user_id, group_id), one=True)

    if not group:
        flash("Subgroup not found.", "danger")
        return redirect(url_for('feed'))

    posts = query_db('''
        SELECT p.id, p.content, p.created_at, u.username, u.id as user_id,
               g.id as group_id, g.name as group_name
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN groups g ON p.group_id = g.id
        WHERE p.group_id = ?
        ORDER BY p.created_at DESC
    ''', (group_id,)) or []

    posts_data = []
    for post in posts:
        reactions = query_db('SELECT reaction_type, COUNT(*) as count FROM reactions WHERE post_id = ? GROUP BY reaction_type', (post['id'],)) or []
        comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post['id'],)) or []

        post_dict = dict(post)
        post_dict['content'], _ = moderate_content(post_dict['content'])
        comments_moderated = []
        for comment in comments_raw:
            comment_dict = dict(comment)
            comment_dict['content'], _ = moderate_content(comment_dict['content'])
            comments_moderated.append(comment_dict)

        posts_data.append({
            'post': post_dict,
            'reactions': reactions,
            'comments': comments_moderated
        })

    return render_template('group_detail.html.j2',
                           group=group,
                           posts=posts_data,
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES)

@app.route('/posts/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    """Handles deleting a post."""
    user_id = session.get('user_id')

    if not user_id:
        flash('You must be logged in to delete a post.', 'danger')
        return redirect(url_for('login'))

    post = query_db('SELECT id, user_id FROM posts WHERE id = ?', (post_id,), one=True)

    if not post:
        flash('Post not found.', 'danger')
        return redirect(url_for('feed'))

    if post['user_id'] != user_id:
        flash('You do not have permission to delete this post.', 'danger')
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()

    flash('Your post was successfully deleted.', 'success')
    return redirect(request.referrer or url_for('feed'))

@app.route('/u/<username>')
def user_profile(username):
    """Displays a user's profile page with moderated bio, posts, and latest comments."""
    user_raw = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user_raw:
        abort(404)

    user = dict(user_raw)
    moderated_bio, _ = moderate_content(user.get('profile', ''))
    user['profile'] = moderated_bio

    posts_raw = query_db('SELECT id, content, user_id, created_at FROM posts WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)) or []
    posts = []
    for post_raw in posts_raw:
        post = dict(post_raw)
        moderated_post_content, _ = moderate_content(post['content'])
        post['content'] = moderated_post_content
        posts.append(post)

    comments_raw = query_db('SELECT id, content, user_id, post_id, created_at FROM comments WHERE user_id = ? ORDER BY created_at DESC LIMIT 100', (user['id'],)) or []
    comments = []
    for comment_raw in comments_raw:
        comment = dict(comment_raw)
        moderated_comment_content, _ = moderate_content(comment['content'])
        comment['content'] = moderated_comment_content
        comments.append(comment)

    followers_count = query_db('SELECT COUNT(*) as cnt FROM follows WHERE followed_id = ?', (user['id'],), one=True)['cnt']
    following_count = query_db('SELECT COUNT(*) as cnt FROM follows WHERE follower_id = ?', (user['id'],), one=True)['cnt']

    is_currently_following = False
    current_user_id = session.get('user_id')
    
    if current_user_id:
        follow_relation = query_db(
            'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
            (current_user_id, user['id']),
            one=True
        )
        if follow_relation:
            is_currently_following = True

    return render_template('user_profile.html.j2', 
                           user=user, 
                           posts=posts, 
                           comments=comments,
                           followers_count=followers_count, 
                           following_count=following_count,
                           is_following=is_currently_following)

@app.route('/u/<username>/followers')
def user_followers(username):
    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        abort(404)
    followers = query_db('''
        SELECT u.username
        FROM follows f
        JOIN users u ON f.follower_id = u.id
        WHERE f.followed_id = ?
    ''', (user['id'],)) or []
    return render_template('user_list.html.j2', user=user, users=followers, title="Followers of")

@app.route('/u/<username>/following')
def user_following(username):
    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        abort(404)
    following = query_db('''
        SELECT u.username
        FROM follows f
        JOIN users u ON f.followed_id = u.id
        WHERE f.follower_id = ?
    ''', (user['id'],)) or []
    return render_template('user_list.html.j2', user=user, users=following, title="Users followed by")

@app.route('/posts/<int:post_id>')
def post_detail(post_id):
    """Displays a single post and its comments, with content moderation applied."""
    post_raw = query_db('''
        SELECT p.id, p.content, p.group_id, p.created_at, u.username, u.id as user_id
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    ''', (post_id,), one=True)

    if not post_raw:
        abort(404)

    # Design Claim 2 Safeguard: Block viewing quarantined posts in detail view
    if post_raw['group_id'] == 999:
        flash('This post is under quarantine review and cannot be viewed in detail.', 'warning')
        return redirect(url_for('feed'))

    post = dict(post_raw)
    moderated_post_content, _ = moderate_content(post['content'])
    post['content'] = moderated_post_content

    reactions = query_db('''
        SELECT reaction_type, COUNT(*) as count
        FROM reactions
        WHERE post_id = ?
        GROUP BY reaction_type
    ''', (post_id,)) or []

    comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post_id,)) or []
    
    comments = []
    for comment_raw in comments_raw:
        comment = dict(comment_raw)
        moderated_comment_content, _ = moderate_content(comment['content'])
        comment['content'] = moderated_comment_content
        comments.append(comment)

    return render_template('post_detail.html.j2',
                           post=post,
                           reactions=reactions,
                           comments=comments,
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES)

@app.route('/about')
def about():
    return render_template('about.html.j2')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html.j2')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        location = request.form.get('location', '')
        birthdate = request.form.get('birthdate', '')
        profile = request.form.get('profile', '')

        hashed_password = generate_password_hash(password)

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(
                'INSERT INTO users (username, password, location, birthdate, profile) VALUES (?, ?, ?, ?, ?)',
                (username, hashed_password, location, birthdate, profile)
            )
            db.commit()

            new_user_id = cur.lastrowid

            session.clear()
            session['user_id'] = new_user_id
            session['username'] = username

            flash(f'Welcome, {username}! Your account has been created.', 'success')
            return redirect(url_for('feed'))

        except sqlite3.IntegrityError:
            flash('Username already taken. Please choose another one.', 'danger')
        finally:
            cur.close()
            db.close()
            
    return render_template('signup.html.j2')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('feed'))
        else:
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html.j2')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/groups/<int:group_id>/join', methods=['POST'])
def join_group(group_id):
    # Design Claim 2 Safeguard: Block users from manually joining automated Quarantine
    if group_id == 999:
        flash("You cannot join the automated Quarantine subgroup.", "warning")
        return redirect(url_for('feed'))
    
    user_id = session.get('user_id')
    if not user_id:
        flash("You must be logged in to join a subgroup.", "danger")
        return redirect(url_for('login'))
    
    query_db('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)', (group_id, user_id))
    flash('Joined subgroup successfully!', 'success')
    return redirect(request.referrer or url_for('feed'))

@app.route('/groups/<int:group_id>/leave', methods=['POST'])
def leave_group(group_id):
    # Design Claim 2 Safeguard: Block users from leaving automated Quarantine
    if group_id == 999:
        flash("You cannot leave the automated Quarantine subgroup.", "warning")
        return redirect(url_for('feed'))
    
    user_id = session.get('user_id')
    if not user_id:
        flash("You must be logged in to leave a subgroup.", "danger")
        return redirect(url_for('login'))
    
    query_db('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, user_id))
    flash('Left subgroup.', 'info')
    return redirect(request.referrer or url_for('feed'))

@app.route('/posts/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    """Handles adding a new comment to a specific post."""
    user_id = session.get('user_id')

    if not user_id:
        flash('You must be logged in to comment.', 'danger')
        return redirect(url_for('login'))

    content = request.form.get('content')

    if content and content.strip():
        db = get_db()
        db.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
                   (post_id, user_id, content))
        db.commit()
        flash('Your comment was added.', 'success')
    else:
        flash('Comment cannot be empty.', 'warning')

    return redirect(request.referrer or url_for('post_detail', post_id=post_id))

@app.route('/comments/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    """Handles deleting a comment."""
    user_id = session.get('user_id')

    if not user_id:
        flash('You must be logged in to delete a comment.', 'danger')
        return redirect(url_for('login'))

    comment = query_db('''
        SELECT c.id, c.user_id, p.user_id as post_author_id
        FROM comments c
        JOIN posts p ON c.post_id = p.id
        WHERE c.id = ?
    ''', (comment_id,), one=True)

    if not comment:
        flash('Comment not found.', 'danger')
        return redirect(request.referrer or url_for('feed'))

    if user_id != comment['user_id'] and user_id != comment['post_author_id']:
        flash('You do not have permission to delete this comment.', 'danger')
        return redirect(request.referrer or url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()

    flash('Comment successfully deleted.', 'success')
    return redirect(request.referrer or url_for('feed'))

@app.route('/react', methods=['POST'])
def add_reaction():
    """Handles adding a new reaction or updating an existing one."""
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to react.", "danger")
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')
    new_reaction_type = request.form.get('reaction')

    if not post_id or not new_reaction_type:
        flash("Invalid reaction request.", "warning")
        return redirect(request.referrer or url_for('feed'))

    db = get_db()

    existing_reaction = query_db('SELECT id FROM reactions WHERE post_id = ? AND user_id = ?',
                                 (post_id, user_id), one=True)

    if existing_reaction:
        db.execute('UPDATE reactions SET reaction_type = ? WHERE id = ?',
                   (new_reaction_type, existing_reaction['id']))
    else:
        db.execute('INSERT INTO reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)',
                   (post_id, user_id, new_reaction_type))

    db.commit()

    return redirect(request.referrer or url_for('feed'))

@app.route('/unreact', methods=['POST'])
def unreact():
    """Handles removing a user's reaction from a post."""
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to unreact.", "danger")
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')

    if not post_id:
        flash("Invalid unreact request.", "warning")
        return redirect(request.referrer or url_for('feed'))

    db = get_db()

    existing_reaction = query_db(
        'SELECT id FROM reactions WHERE post_id = ? AND user_id = ?',
        (post_id, user_id),
        one=True
    )

    if existing_reaction:
        db.execute('DELETE FROM reactions WHERE id = ?', (existing_reaction['id'],))
        db.commit()
        flash("Reaction removed.", "success")
    else:
        flash("No reaction to remove.", "info")

    return redirect(request.referrer or url_for('feed'))

@app.route('/u/<int:user_id>/follow', methods=['POST'])
def follow_user(user_id):
    """Handles the logic for the current user to follow another user."""
    follower_id = session.get('user_id')

    if not follower_id:
        flash("You must be logged in to follow users.", "danger")
        return redirect(url_for('login'))

    if follower_id == user_id:
        flash("You cannot follow yourself.", "warning")
        return redirect(request.referrer or url_for('feed'))

    user_to_follow = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user_to_follow:
        flash("The user you are trying to follow does not exist.", "danger")
        return redirect(request.referrer or url_for('feed'))
        
    db = get_db()
    try:
        db.execute('INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)',
                   (follower_id, user_id))
        db.commit()
        username_to_follow = query_db('SELECT username FROM users WHERE id = ?', (user_id,), one=True)['username']
        flash(f"You are now following {username_to_follow}.", "success")
    except sqlite3.IntegrityError:
        flash("You are already following this user.", "info")

    return redirect(request.referrer or url_for('feed'))

@app.route('/u/<int:user_id>/unfollow', methods=['POST'])
def unfollow_user(user_id):
    """Handles the logic for the current user to unfollow another user."""
    follower_id = session.get('user_id')

    if not follower_id:
        flash("You must be logged in to unfollow users.", "danger")
        return redirect(url_for('login'))

    db = get_db()
    cur = db.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?',
               (follower_id, user_id))
    db.commit()

    if cur.rowcount > 0:
        username_unfollowed = query_db('SELECT username FROM users WHERE id = ?', (user_id,), one=True)['username']
        flash(f"You have unfollowed {username_unfollowed}.", "success")
    else:
        flash("You were not following this user.", "info")

    return redirect(request.referrer or url_for('feed'))

@app.route('/admin')
def admin_dashboard():
    """Displays the admin dashboard with users, posts, and comments, sorted by risk."""

    if session.get('username') != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('feed'))

    RISK_LEVELS = { "HIGH": 5, "MEDIUM": 3, "LOW": 1 }
    PAGE_SIZE = 50

    def get_risk_profile(score):
        if score >= RISK_LEVELS["HIGH"]:
            return "HIGH", 3
        elif score >= RISK_LEVELS["MEDIUM"]:
            return "MEDIUM", 2
        elif score >= RISK_LEVELS["LOW"]:
            return "LOW", 1
        return "NONE", 0

    try:
        users_page = int(request.args.get('users_page', 1))
        posts_page = int(request.args.get('posts_page', 1))
        comments_page = int(request.args.get('comments_page', 1))
    except ValueError:
        users_page = 1
        posts_page = 1
        comments_page = 1
    
    current_tab = request.args.get('tab', 'users')
    users_offset = (users_page - 1) * PAGE_SIZE
    
    all_users_raw = query_db('SELECT id, username, profile, created_at FROM users') or []
    all_users = []
    for user in all_users_raw:
        user_dict = dict(user)
        user_risk_score = user_risk_analysis(user_dict['id'])
        risk_label, risk_sort_key = get_risk_profile(user_risk_score)
        user_dict['risk_label'] = risk_label
        user_dict['risk_sort_key'] = risk_sort_key
        user_dict['risk_score'] = min(5.0, round(user_risk_score, 2))
        all_users.append(user_dict)

    all_users.sort(key=lambda x: x['risk_score'], reverse=True)
    total_users = len(all_users)
    users = all_users[users_offset : users_offset + PAGE_SIZE]
    total_users_pages = (total_users + PAGE_SIZE - 1) // PAGE_SIZE

    posts_offset = (posts_page - 1) * PAGE_SIZE
    total_posts_row = query_db('SELECT COUNT(*) as count FROM posts', one=True)
    total_posts_count = total_posts_row['count'] if total_posts_row else 0
    total_posts_pages = (total_posts_count + PAGE_SIZE - 1) // PAGE_SIZE

    posts_raw = query_db(f'''
        SELECT p.id, p.content, p.created_at, u.username, u.created_at as user_created_at
        FROM posts p JOIN users u ON p.user_id = u.id
        ORDER BY p.id DESC
        LIMIT ? OFFSET ?
    ''', (PAGE_SIZE, posts_offset)) or []
    posts = []
    for post in posts_raw:
        post_dict = dict(post)
        _, base_score = moderate_content(post_dict['content'])
        final_score = base_score 
        author_created_dt = post_dict['user_created_at']
        author_age_days = (datetime.utcnow() - author_created_dt).days
        if author_age_days < 7:
            final_score *= 1.5
        risk_label, risk_sort_key = get_risk_profile(final_score)
        post_dict['risk_label'] = risk_label
        post_dict['risk_sort_key'] = risk_sort_key
        post_dict['risk_score'] = round(final_score, 2)
        posts.append(post_dict)

    posts.sort(key=lambda x: x['risk_score'], reverse=True)

    comments_offset = (comments_page - 1) * PAGE_SIZE
    total_comments_row = query_db('SELECT COUNT(*) as count FROM comments', one=True)
    total_comments_count = total_comments_row['count'] if total_comments_row else 0
    total_comments_pages = (total_comments_count + PAGE_SIZE - 1) // PAGE_SIZE

    comments_raw = query_db(f'''
        SELECT c.id, c.content, c.created_at, u.username, u.created_at as user_created_at
        FROM comments c JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC
        LIMIT ? OFFSET ?
    ''', (PAGE_SIZE, comments_offset)) or []
    comments = []
    for comment in comments_raw:
        comment_dict = dict(comment)
        _, score = moderate_content(comment_dict['content'])
        author_created_dt = comment_dict['user_created_at']
        author_age_days = (datetime.utcnow() - author_created_dt).days
        if author_age_days < 7:
            score *= 1.5
        risk_label, risk_sort_key = get_risk_profile(score)
        comment_dict['risk_label'] = risk_label
        comment_dict['risk_sort_key'] = risk_sort_key
        comment_dict['risk_score'] = round(score, 2)
        comments.append(comment_dict)

    comments.sort(key=lambda x: x['risk_score'], reverse=True)

    return render_template('admin.html.j2', 
                           users=users, 
                           posts=posts, 
                           comments=comments,
                           users_page=users_page,
                           total_users_pages=total_users_pages,
                           users_has_next=(users_page < total_users_pages),
                           users_has_prev=(users_page > 1),
                           posts_page=posts_page,
                           total_posts_pages=total_posts_pages,
                           posts_has_next=(posts_page < total_posts_pages),
                           posts_has_prev=(posts_page > 1),
                           comments_page=comments_page,
                           total_comments_pages=total_comments_pages,
                           comments_has_next=(comments_page < total_comments_pages),
                           comments_has_prev=(comments_page > 1),
                           current_tab=current_tab,
                           PAGE_SIZE=PAGE_SIZE)

@app.route('/admin/delete/user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))
        
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account from the admin panel.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash(f'User {user_id} and all their content has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/post/<int:post_id>', methods=['POST'])
def admin_delete_post(post_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash(f'Post {post_id} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/comment/<int:comment_id>', methods=['POST'])
def admin_delete_comment(comment_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    flash(f'Comment {comment_id} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/rules')
def rules():
    return render_template('rules.html.j2')

@app.template_global()
def loop_color(user_id):
    h = hashlib.md5(str(user_id).encode()).hexdigest()
    r = int(h[0:2], 16)
    g = int(h[2:4], 16)
    b = int(h[4:6], 16)
    return f'rgb({r % 128 + 80}, {g % 128 + 80}, {b % 128 + 80})'


# ----- Coding Assignment #2 Implementations -----

# Assignment 2.2: User Risk Analysis
def user_risk_analysis(user_id):
    """
    Evaluates aggregate user risk level based on user history, violation scores,
    and account age multipliers.
    """
    user = query_db('SELECT id, profile, created_at FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return 0.0

    # Step 1: Profile Score
    profile_text = user['profile'] or ''
    _, profile_score = moderate_content(profile_text)

    # Step 2: Average Post Score
    posts = query_db('SELECT content FROM posts WHERE user_id = ?', (user_id,)) or []
    if posts:
        post_scores = [moderate_content(p['content'])[1] for p in posts]
        average_post_score = sum(post_scores) / len(post_scores)
    else:
        average_post_score = 0.0

    # Step 3: Average Comment Score
    comments = query_db('SELECT content FROM comments WHERE user_id = ?', (user_id,)) or []
    if comments:
        comment_scores = [moderate_content(c['content'])[1] for c in comments]
        average_comment_score = sum(comment_scores) / len(comment_scores)
    else:
        average_comment_score = 0.0

    # Step 4: Combine Scores
    content_risk_score = (profile_score * 1.0) + (average_post_score * 3.0) + (average_comment_score * 1.0)

    # Step 5: Apply Age Multiplier
    created_at = user['created_at']
    if isinstance(created_at, str):
        try:
            created_at = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            created_at = datetime.strptime(created_at.split('.')[0], '%Y-%m-%d %H:%M:%S')

    account_age_days = (datetime.utcnow() - created_at).days

    if account_age_days < 7:
        user_risk_score = content_risk_score * 1.5
    elif account_age_days < 30:
        user_risk_score = content_risk_score * 1.2
    else:
        user_risk_score = content_risk_score

    # Step 6: Final Capping (Upper bound 5.0)
    return min(5.0, user_risk_score)

# Assignment 2.1: Content Moderation & Censorship
def moderate_content(content):
    """
    Moderates text content against loaded censorship rules and calculates severity scores.
    Design Claim 1: Prescreens, degrades mild profanity, and removes severe violations.
    """
    if not content:
        return "", 0.0

    # Stage 1.1: Severe Violation Checks
    for word in TIER1_WORDS:
        pattern = rf'\b{re.escape(word)}\b'
        if re.search(pattern, content, flags=re.IGNORECASE):
            return "[content removed due to severe violation]", 5.0

    for phrase in TIER2_PHRASES:
        pattern = rf'\b{re.escape(phrase)}\b'
        if re.search(pattern, content, flags=re.IGNORECASE):
            return "[content removed due to spam/scam policy]", 5.0

    # Stage 1.2: Scored Violations & Filtering
    moderated_content = content
    score = 0.0

    # Rule 1.2.1 (Tier 3 Words): Mask with asterisks, +2.0 per match
    for word in TIER3_WORDS:
        pattern = rf'\b{re.escape(word)}\b'
        matches = re.findall(pattern, moderated_content, flags=re.IGNORECASE)
        if matches:
            score += 2.0 * len(matches)
            moderated_content = re.sub(
                pattern, 
                lambda m: '*' * len(m.group(0)), 
                moderated_content, 
                flags=re.IGNORECASE
            )

    # Rule 1.2.2 (External Links): Replace URL with placeholder, +2.0 per match
    url_pattern = r'https?://\S+|www\.\S+'
    urls = re.findall(url_pattern, moderated_content)
    if urls:
        score += 2.0 * len(urls)
        moderated_content = re.sub(url_pattern, '[link removed]', moderated_content)

    # Rule 1.2.3 (Excessive Capitalization): >15 chars & >70% uppercase -> +0.5 score
    alpha_chars = [c for c in content if c.isalpha()]
    if len(alpha_chars) > 15:
        upper_chars = [c for c in alpha_chars if c.isupper()]
        if (len(upper_chars) / len(alpha_chars)) > 0.70:
            score += 0.5
    
    return moderated_content, score

# Assignment 3.1 Stub
def recommend(user_id, filter_following):
    recommended_posts = []
    return recommended_posts

if __name__ == '__main__':
    app.run(debug=True, port=8080)