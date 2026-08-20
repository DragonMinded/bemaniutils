from typing import Dict, Any, Optional
from flask import (
    Blueprint,
    request,
    redirect,
    Response,
    url_for,
    make_response,
    render_template,
)

from bemani.common import CardCipher, CardCipherException, AESCipher, Time, decode_user_provided
from bemani.frontend.app import (
    loginrequired,
    loginprohibited,
    success,
    error,
    jsonify,
    valid_email,
    valid_username,
    valid_pin,
    render_react,
)
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g

account_pages = Blueprint(
    "account_pages",
    __name__,
    template_folder=templates_location,
    static_folder=static_location,
)


@account_pages.route("/login", methods=["POST"])
@loginprohibited
def login() -> Response:
    username = request.form["username"]
    password = request.form["password"]

    userid = g.data.local.user.from_username(username)
    if userid is None:
        error("Unrecognized username or password!")
        return Response(
            render_template(
                "account/login.html",
                **{"title": "Log In", "show_navigation": False, "username": username},
            )
        )

    if g.data.local.user.validate_password(userid, password):
        aes = AESCipher(g.config.secret_key)
        sessionID = g.data.local.user.create_session(userid, expiration=90 * 86400)
        response = make_response(redirect(url_for("home_pages.viewhome")))
        response.set_cookie(
            "SessionID",
            aes.encrypt(sessionID),
            expires=Time.now() + (90 * Time.SECONDS_IN_DAY),
        )
        return response
    else:
        error("Unrecognized username or password!")
        return Response(
            render_template(
                "account/login.html",
                **{"title": "Log In", "show_navigation": False, "username": username},
            )
        )


@account_pages.route("/login")
@loginprohibited
def viewlogin() -> Response:
    return Response(render_template("account/login.html", **{"title": "Log In", "show_navigation": False}))


def recover_display(username: str, token: Optional[str], card_number: Optional[str]) -> Response:
    return Response(render_template(
        "account/recover.html",
        **{"title": "Recover Password", "show_navigation": False, "token": token, "card_number": card_number, "username": username},
    ))


@account_pages.route("/recover", methods=["POST"])
@loginprohibited
def recover() -> Response:
    username = request.form["username"]
    token = request.form.get("token", "")
    password1 = request.form["password1"]
    password2 = request.form["password2"]
    card_number = request.form.get("card_number", "")
    pin = request.form.get("pin", "")

    # Figure out what style of recovery it is.
    if token:
        # Now, make sure this account recovery token is valid.
        userid = g.data.local.user.from_recovery(token)
        if userid is None:
            error("Recovery token is invalid or expired!")
            return recover_display(username, token, card_number)

        # And make sure the user is valid and matches this recovery token.
        user = g.data.local.user.get_user(userid)
        if user is None:
            error("Recovery token is invalid or expired!")
            return recover_display(username, token, card_number)

        # Be a little lenient with username spelling here.
        if user.username.lower() != username.lower():
            error("Recovery token is not for this account!")
            return recover_display(username, token, card_number)

    elif card_number:
        # First, try to convert the card to a valid E004 ID
        try:
            cardid = decode_user_provided(g.config, card_number)
        except CardCipherException:
            error("Invalid card number!")
            return recover_display(username, token, card_number)

        # Now, see if this card ID exists already
        userid = g.data.local.user.from_cardid(cardid)
        if userid is None:
            error("The specified card is not for this account!")
            return recover_display(username, token, card_number)

        # Now, make sure this card and user are linked
        user = g.data.local.user.get_user(userid)
        if user is None:
            error("The specified card is not for this account!")
            return recover_display(username, token, card_number)

        # Be a little lenient with username spelling here.
        if user.username.lower() != username.lower():
            error("The specified card is not for this account!")
            return recover_display(username, token, card_number)

        # Now, see if the pin is correct
        if not g.data.local.user.validate_pin(userid, pin):
            error("The entered PIN does not match the PIN on the card!")
            return recover_display(username, token, card_number)

    else:
        error("Recovery token is invalid or expired!")
        return recover_display(username, token, card_number)

    # Now, make sure that the passwords match
    if password1 != password2:
        error("Passwords do not match each other!")
        return recover_display(username, token, card_number)

    # Now, make sure passwords are long enough
    if len(password1) < 6:
        error("Password is not long enough!")
        return recover_display(username, token, card_number)

    # Now, update the account.
    g.data.local.user.update_password(userid, password1)
    g.data.local.user.destroy_recovery(token)
    success("Successfully updated password!")
    response = make_response(redirect(url_for("account_pages.login")))
    return response


@account_pages.route("/recover", defaults={"recovery": None})
@account_pages.route("/recover/<recovery>")
@loginprohibited
def viewrecover(recovery: Optional[str]) -> Response:
    return recover_display("", recovery, "")


def register_display(card_number: str, username: str, email: str) -> Response:
    return Response(
        render_template(
            "account/register.html",
            **{
                "title": "Register New Account",
                "show_navigation": False,
                "card_number": card_number,
                "username": username,
                "email": email,
            },
        )
    )


@account_pages.route("/register", methods=["POST"])
@loginprohibited
def register() -> Response:
    card_number = request.form["card_number"]
    pin = request.form["pin"]
    username = request.form["username"]
    email = request.form["email"]
    password1 = request.form["password1"]
    password2 = request.form["password2"]

    # First, try to convert the card to a valid E004 ID
    try:
        cardid = decode_user_provided(g.config, card_number)
    except CardCipherException:
        error("Invalid card number!")
        return register_display(card_number, username, email)

    # Now, see if this card ID exists already
    userid = g.data.local.user.from_cardid(cardid)
    if userid is None:
        error("This card has not been used on the network yet!")
        return register_display(card_number, username, email)

    # Now, make sure this user doesn't already have an account
    user = g.data.local.user.get_user(userid)
    if user.username is not None or user.email is not None:
        error("This card is already in use!")
        return register_display(card_number, username, email)

    # Now, see if the pin is correct
    if not g.data.local.user.validate_pin(userid, pin):
        error("The entered PIN does not match the PIN on the card!")
        return register_display(card_number, username, email)

    # Now, see if the username is valid
    if not valid_username(username):
        error("Invalid username!")
        return register_display(card_number, username, email)

    # Now, check whether the username is already in use
    if g.data.local.user.from_username(username) is not None:
        error("The chosen username is already in use!")
        return register_display(card_number, username, email)

    # Now, see if the email address is valid
    if not valid_email(email):
        error("Invalid email address!")
        return register_display(card_number, username, email)

    # Now, make sure that the passwords match
    if password1 != password2:
        error("Passwords do not match each other!")
        return register_display(card_number, username, email)

    # Now, make sure passwords are long enough
    if len(password1) < 6:
        error("Password is not long enough!")
        return register_display(card_number, username, email)

    # Now, create the account.
    user.username = username
    user.email = email
    g.data.local.user.put_user(user)
    g.data.local.user.update_password(userid, password1)

    # Now, log them into that created account!
    aes = AESCipher(g.config.secret_key)
    sessionID = g.data.local.user.create_session(userid)
    success("Successfully registered account!")
    response = make_response(redirect(url_for("home_pages.viewhome")))
    response.set_cookie("SessionID", aes.encrypt(sessionID))
    return response


@account_pages.route("/register")
@loginprohibited
def viewregister() -> Response:
    return Response(
        render_template(
            "account/register.html",
            **{"title": "Register New Account", "show_navigation": False},
        )
    )


@account_pages.route("/logout")
@loginrequired
def logout() -> Response:
    g.data.local.user.destroy_session(g.sessionID)
    response = make_response(redirect(url_for("account_pages.viewlogin")))
    response.set_cookie("SessionID", "", expires=0)
    success("Successfully logged out!")
    return response


@account_pages.route("/account")
@loginrequired
def viewaccount() -> Response:
    user = g.data.local.user.get_user(g.userID)
    return render_react(
        "Account Management",
        "account/account.react.js",
        {
            "email": user.email,
            "username": user.username,
        },
        {
            "updateemail": url_for("account_pages.updateemail"),
            "updatepin": url_for("account_pages.updatepin"),
            "updatepassword": url_for("account_pages.updatepassword"),
        },
    )


@account_pages.route("/account/cards")
@loginrequired
def viewcards() -> Response:
    cards = [CardCipher.encode(card) for card in g.data.local.user.get_cards(g.userID)]
    return render_react(
        "Card Management",
        "account/cards.react.js",
        {
            "cards": cards,
        },
        {
            "addcard": url_for("account_pages.addcard"),
            "removecard": url_for("account_pages.removecard"),
            "listcards": url_for("account_pages.listcards"),
        },
    )


@account_pages.route("/account/cards/list")
@jsonify
@loginrequired
def listcards() -> Dict[str, Any]:
    # Return new card list
    cards = [CardCipher.encode(card) for card in g.data.local.user.get_cards(g.userID)]
    return {
        "cards": cards,
    }


@account_pages.route("/account/cards/add", methods=["POST"])
@jsonify
@loginrequired
def addcard() -> Dict[str, Any]:
    # Grab card, convert it
    card = request.get_json()["card"]
    try:
        cardid = decode_user_provided(g.config, card)
    except CardCipherException:
        raise Exception("Invalid card number!")

    # See if it is already claimed
    userid = g.data.local.user.from_cardid(cardid)
    if userid is not None:
        raise Exception("This card is already in use!")

    # Add it to this user's account
    g.data.local.user.add_card(g.userID, cardid)

    # Return new card list
    cards = [CardCipher.encode(card) for card in g.data.local.user.get_cards(g.userID)]
    return {
        "cards": cards,
    }


@account_pages.route("/account/cards/remove", methods=["POST"])
@jsonify
@loginrequired
def removecard() -> Dict[str, Any]:
    # Grab card, convert it
    card = request.get_json()["card"]
    try:
        cardid = decode_user_provided(g.config, card)
    except CardCipherException:
        raise Exception("Invalid card number!")

    # Make sure it is our card
    userid = g.data.local.user.from_cardid(cardid)
    if userid != g.userID:
        raise Exception("This card is not yours to delete!")

    # Remove it from this user's account
    g.data.local.user.destroy_card(g.userID, cardid)

    # Return new card list
    cards = [CardCipher.encode(card) for card in g.data.local.user.get_cards(g.userID)]
    return {
        "cards": cards,
    }


@account_pages.route("/account/email/update", methods=["POST"])
@jsonify
@loginrequired
def updateemail() -> Dict[str, Any]:
    email = request.get_json()["email"]
    password = request.get_json()["password"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Make sure current password matches
    if not g.data.local.user.validate_password(g.userID, password):
        raise Exception("Current password is not correct!")

    if not valid_email(email):
        raise Exception("Invalid email address!")

    # Update and save
    user.email = email
    g.data.local.user.put_user(user)

    # Return updated email
    return {
        "email": email,
    }


@account_pages.route("/account/pin/update", methods=["POST"])
@jsonify
@loginrequired
def updatepin() -> Dict[str, Any]:
    old = request.get_json()["old"]
    pin1 = request.get_json()["pin1"]
    pin2 = request.get_json()["pin2"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Make sure current password matches
    if not g.data.local.user.validate_password(g.userID, old):
        raise Exception("Current password is not correct!")

    # Make sure the PIN is valid.
    if not valid_pin(pin1, "card"):
        raise Exception("Invalid PIN, must be exactly 4 digits!")
    if not valid_pin(pin2, "card"):
        raise Exception("Invalid PIN, must be exactly 4 digits!")

    # Make sure it was confirmed twice.
    if pin1 != pin2:
        raise Exception("PINs do not match each other!")

    # Update and save
    g.data.local.user.update_pin(g.userID, pin1)

    # Return nothing
    return {}


@account_pages.route("/account/password/update", methods=["POST"])
@jsonify
@loginrequired
def updatepassword() -> Dict[str, Any]:
    old = request.get_json()["old"]
    new1 = request.get_json()["new1"]
    new2 = request.get_json()["new2"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Make sure current password matches
    if not g.data.local.user.validate_password(g.userID, old):
        raise Exception("Current password is not correct!")

    # Now, make sure that the passwords match
    if new1 != new2:
        raise Exception("Passwords do not match each other!")

    # Now, make sure passwords are long enough
    if len(new1) < 6:
        raise Exception("Password is not long enough!")

    # Update and save
    g.data.local.user.update_password(g.userID, new1)

    # Return nothing
    return {}
