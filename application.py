import os

# solve import error

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    """from db created in buy, SELECT user_id row and display table"""
    """session[user_ID]"""
    """lookup for the price of holding stock"""
    user_data = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    cash = user_data[0]['cash']

    # pull all transactions belonging to user
    portfolio = db.execute("SELECT stock, share FROM portfolio WHERE user_id = ? AND share != 0", session["user_id"])

    all_total = cash

    if portfolio:
        # determine current price, stock total value and grand total value
        for stock in portfolio:
            price = lookup(stock['stock'])['price']
            total = stock['share'] * price
            stock.update({'price': usd(price), 'total': usd(total)})
            all_total += total

    return render_template("index.html", stocks=portfolio, cash=usd(cash), total=usd(all_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        """display form to buy a stock(symbol, shares)"""
        return render_template("buy.html")

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("no symbol found")

        if not request.form.get("shares"):
            return apology("must request more than 1 share")

        if (request.form.get("shares")).isnumeric() == False:
            return apology("shares must be an integer")

        if int(request.form.get("shares")) <= 0:
            return apology("shares must be an integer")

        quote = lookup(request.form.get("symbol"))

        if quote == None:
            return apology("no symbol found")

        cost = int(request.form.get("shares")) * quote['price']
        print(cost)

        # purchase the stock if the user can afford it
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        if cost > cash[0]["cash"]:
            return apology("need more cash")

        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", cost, session["user_id"])

        db.execute("INSERT INTO transactions (user_id, stock, share, price, date) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], quote["symbol"], int(request.form.get("shares")), quote['price'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        portfolio = db.execute("SELECT share FROM portfolio WHERE stock = ? AND user_id = ?",
                               quote["symbol"], session["user_id"])

        if not portfolio:
            db.execute("INSERT INTO portfolio (user_id, stock, share) VALUES (?, ?, ?)",
                       session["user_id"], quote["symbol"], int(request.form.get("shares")))

        """if symbol is already in portfolio, update quantity of shares and total"""
        if portfolio:
            db.execute("UPDATE portfolio SET share = share + ? WHERE stock = ? AND user_id = ?",
                       int(request.form.get("shares")), quote["symbol"], session["user_id"])

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    """to do this, you need to be created table to track information and to show history at BUY and SELL"""
    portfolio = db.execute("SELECT stock, share, price, date FROM transactions WHERE user_id = ?", session["user_id"])

    if not portfolio:
        return apology("don't have transaction history yet")

    return render_template("history.html", stocks=portfolio)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""

    # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # query database for username
        user = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # ensure username exists and password is correct
        if len(user) != 1 or not check_password_hash(user[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password")

        # remember which user has logged in
        session["user_id"] = user[0]["id"]

        # redirect user to home page
        return redirect("/")

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return render_template("login.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        """display form to request a stock quote"""
        return render_template("quote.html")

    if request.method == "POST":
        """lookup the stock symbol by calling the lookup function, and display the result"""
        """lookup function is in helpers.py, lookup(symbol) returns name, price, symbol in python dictionary, if not symbol return None"""

        if not request.form.get("symbol"):
            return apology("no symbol found")

        # pull quote from yahoo finance
        quote = lookup(request.form.get("symbol"))

        # check is valid stock name provided
        """if lookup returns None, display apology"""
        if quote == None:
            return apology("no symbol found")

        # stock name is valid
        else:
            quote["price"] = usd(quote["price"])

            return render_template("quoted.html", quote=quote)


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():

    if request.method == "GET":
        return render_template("changepassword.html")

    if request.method == "POST":

        if not request.form.get("password"):
            return apology("no password found")

        elif not request.form.get("confirmation"):
            return apology("no password confirmation")

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("must provide same password")

        password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", password, session["user_id"])

        return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("no username found")

        elif len(db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))) != 0:
            return apology("username already used")

        elif not request.form.get("password"):
            return apology("no password found")

        elif not request.form.get("confirmation"):
            return apology("no password confirmation")

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("must provide same password")

        password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        # insert user to the database
        username = request.form.get("username")

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, password)

        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":
        """display form to sell a stock"""
        portfolio = db.execute("SELECT stock FROM portfolio WHERE user_id = ? AND share != 0", session["user_id"])

        return render_template("sell.html", stocks=portfolio)

    if request.method == "POST":
        """sell the specific number of shares of stock, and update users' cash"""
        """check if the user own the stock, have number of shares"""

        if not request.form.get("symbol"):
            return apology("no symbol found")

        if not request.form.get("shares"):
            return apology("must provide shares")

        if (request.form.get("shares")).isnumeric() == False:
            return apology("shares must be an integers")

        # ensure number of shares is valid
        if int(request.form.get("shares")) <= 0:
            return apology("shares must be an integer")

        holding = db.execute("SELECT share FROM portfolio WHERE stock = ?", request.form.get("symbol"))

        # check that number of shares being sold does not exceed quantity in portfolio
        if int(request.form.get("shares")) > holding[0]['share']:
            return apology("cant't sell more shares than you are holding")

        # pull quote from yahoo finance
        quote = lookup(request.form.get("symbol"))

        # check is valid stock name provided
        if quote == None:
            return apology("symbol not valid")

        # calculate cost of transaction
        cost = int(request.form.get("shares")) * quote['price']

        # update cash amount in users database
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", cost, session["user_id"])

        # add transaction to transaction database
        transaction = db.execute("INSERT INTO transactions (user_id, stock, share, price, date) VALUES (?, ?, ?, ?, ?)",
                                 session["user_id"], quote["symbol"], -int(request.form.get("shares")), quote['price'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # update quantity of shares and total
        db.execute("UPDATE portfolio SET share = share - ? WHERE stock = ?", int(request.form.get("shares")), quote["symbol"])

        return redirect("/")

    return apology("try again")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
