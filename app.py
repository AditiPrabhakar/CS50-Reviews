from cs50 import SQL
from flask import Flask, render_template, request, session, redirect, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///reviews.db")

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

@app.route("/")
def index():
    return render_template('index.html')


@app.route("/homepage")
@login_required
def home():
    user_id = session["user_id"]

    # Fetch user profile data
    user_data = db.execute(
        "SELECT username, reviews_count, total_upvotes, total_downvotes FROM users WHERE id = ?",
        (user_id)
    )
    
    # Ensure data exists
    if user_data:
        profile_data = user_data[0]  # Fetch the first (and only) result
    else:
        profile_data = {
            "username": "Unknown",
            "reviews_count": 0,
            "total_upvotes": 0,
            "total_downvotes": 0
        }

    # Pass the profile data to the template
    return render_template('home.html', profile=profile_data)



@app.route("/postReview", methods=["GET", "POST"])
@login_required
def post_review():
    if request.method == "POST":
        name = request.form.get("name")
        review = request.form.get("review")
        if not name or not review:
            return render_template("failure.html", error=400, message="Both fields are required.")

        user_data = db.execute('SELECT username, reviews_count FROM users WHERE id = ?', session.get('user_id'))
        username = user_data[0]["username"] if user_data else None

        if name != username:
            return render_template("failure.html", error=400, message="Kindly enter your correct username.")

        db.execute('INSERT INTO reviews (user_id, username, review) VALUES (?, ?, ?)', session.get("user_id"), username, review)

        reviews_count = int(user_data[0]["reviews_count"])

        db.execute('UPDATE users SET reviews_count = ?', reviews_count + 1)

        return render_template("post-review.html", success="Thank you for your review, " + name + "!")

    return render_template("post-review.html")


@app.route("/showReviews", methods=["GET", "POST"])
@login_required
def show_reviews():
    if request.method == "POST":
        # Get the form data
        review_id = request.form.get("review_id")
        vote_type = request.form.get("vote_type")

        # Get user_id from session
        user_id = session["user_id"]

        # Check if review exists
        review = db.execute("SELECT * FROM reviews WHERE id = ?", review_id)
        if not review:
            return redirect("/showReviews")

        review = review[0]  # Since db.execute returns a list

        # Check if user already voted on this review
        existing_vote = db.execute(
            "SELECT * FROM votes WHERE user_id = ? AND review_id = ?", user_id, review_id
        )

        if existing_vote:
            # If user already voted, handle changing vote
            if existing_vote[0]["vote_type"] != vote_type:
                # Update the votes based on new vote type
                if vote_type == "upvote":
                    # Update review upvotes and downvotes
                    db.execute(
                        "UPDATE reviews SET upvotes = upvotes + 1, downvotes = downvotes - 1 WHERE id = ?", review_id)
                    # Update user total votes
                    db.execute(
                        "UPDATE users SET total_upvotes = total_upvotes + 1, total_downvotes = total_downvotes - 1 WHERE id = ?", review["user_id"])
                elif vote_type == "downvote":
                    db.execute(
                        "UPDATE reviews SET upvotes = upvotes - 1, downvotes = downvotes + 1 WHERE id = ?", review_id)
                    db.execute(
                        "UPDATE users SET total_upvotes = total_upvotes - 1, total_downvotes = total_downvotes + 1 WHERE id = ?", review["user_id"])

                # Update the vote type in the votes table
                db.execute("UPDATE votes SET vote_type = ? WHERE user_id = ? AND review_id = ?",
                           vote_type, user_id, review_id)
        else:
            # If the user has not voted before, insert their vote
            if vote_type == "upvote":
                db.execute(
                    "UPDATE reviews SET upvotes = upvotes + 1 WHERE id = ?", review_id)
                db.execute(
                    "UPDATE users SET total_upvotes = total_upvotes + 1 WHERE id = ?", review["user_id"])
            elif vote_type == "downvote":
                db.execute(
                    "UPDATE reviews SET downvotes = downvotes + 1 WHERE id = ?", review_id)
                db.execute(
                    "UPDATE users SET total_downvotes = total_downvotes + 1 WHERE id = ?", review["user_id"])

            # Insert the new vote into the votes table
            db.execute("INSERT INTO votes (user_id, review_id, vote_type) VALUES (?, ?, ?)",
                       user_id, review_id, vote_type)

        return redirect("/showReviews")

    # For GET request, fetch all reviews along with the user's upvote/downvote status
    reviews = db.execute(
        "SELECT reviews.id, reviews.username, reviews.review, reviews.upvotes, reviews.downvotes, users.total_upvotes, users.total_downvotes, "
        "CASE WHEN EXISTS (SELECT 1 FROM votes WHERE user_id = ? AND review_id = reviews.id AND vote_type = 'upvote') THEN 1 ELSE 0 END AS voted_up, "
        "CASE WHEN EXISTS (SELECT 1 FROM votes WHERE user_id = ? AND review_id = reviews.id AND vote_type = 'downvote') THEN 1 ELSE 0 END AS voted_down "
        "FROM reviews JOIN users ON reviews.user_id = users.id",
        session["user_id"], session["user_id"]
    )

    return render_template("showreviews.html", reviews=reviews)



@app.route("/faqs")
@login_required
def faqs():
    return render_template("faqs.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("failure.html", message="must provide username", error=403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("failure.html", message="must provide password", error=403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get(
                "username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return render_template("failure.html", message="invalid username and/or password", error=403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/homepage")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def register():
    username = request.form.get("username")

    if request.method == "POST":
        if not username:
            return render_template("failure.html", message="must provide username", error="400")

        elif not request.form.get("password"):
            return render_template("failure.html", message="must provide password", error="400")

        elif request.form.get("password") != request.form.get("confirmation"):
            return render_template("failure.html", message="passwords don't match", error="400")

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", username
        )

        if len(rows) != 0:
            return render_template("failure.html", message="username already exists", error="400")

        user_id = db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            username, generate_password_hash(request.form.get("password"))
        )

        session["user_id"] = user_id

        return redirect("/homepage")
    else:
        return render_template("signup.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

