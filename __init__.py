from typing import TYPE_CHECKING
from flask import flash, redirect, request, session


from CTFd.models import db, Users
from CTFd.plugins.sso_ui.cas import CASClient
from CTFd.utils import get_app_config, set_config
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user

if TYPE_CHECKING:
    from CTFd import CTFdFlask


def load(app: "CTFdFlask"):
    override_login = get_app_config("SSO_OVERRIDE_LOGIN", False)

    def retrieve_user_from_database(username):
        user = Users.query.filter_by(email=username + "@ui.ac.id").first()
        if user is not None:
            return user

    def create_user(username: str):
        with app.app_context():
            user = Users(email=username + "@ui.ac.id", name=username)
            db.session.add(user)
            db.session.commit()
            db.session.flush()
            return user

    def create_or_get_user(username: str):
        user = retrieve_user_from_database(username)
        if not user:
            user = create_user(username)

        return user

    @app.route("/auth/sso", methods=["GET"])
    def confirm_auth_provider():
        cas = CASClient(request.host_url + "auth/sso")
        ticket = request.args.get("ticket", "")
        if not ticket:
            return redirect(cas.login_url)

        try:
            data = cas.authenticate(ticket).get("serviceResponse", {})
            if "authenticationSuccess" not in data:
                raise Exception("SSO failed")
        except:
            flash("Failed to authenticate to SSO UI", category="error")
            return redirect("/")

        data = data["authenticationSuccess"]
        user = create_or_get_user(data["user"])

        session.regenerate()
        login_user(user)
        return redirect("/")

    if not override_login:
        return

    set_config("registration_visibility", False)
    app.view_functions["auth.login"] = lambda: redirect("/auth/sso")
    app.view_functions["auth.register"] = lambda: redirect("/")
    app.view_functions["auth.reset_password"] = lambda: redirect("/")
    app.view_functions["auth.confirm"] = lambda: redirect("/")
