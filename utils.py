from flask import session, redirect, url_for, request, render_template
from functools import wraps

def check_in_session(id):
    return id in session.get('posts', [])

def protected(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return render_template("error.html")
        return func(*args, **kwargs)
    return wrapper