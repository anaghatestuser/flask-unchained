from http import HTTPStatus

from flask import abort, request, session

from flask_unchained import Controller, injectable
from flask_unchained import lazy_gettext as _
from flask_unchained import route, url_for

from ...security import SecurityService, UserManager, anonymous_user_required
from ..exceptions import OAuthEmailError
from ..extensions import OAuth
from ..services import OAuthService


class OAuthController(Controller):
    oauth: OAuth = injectable
    oauth_service: OAuthService = injectable
    security_service: SecurityService = injectable
    user_manager: UserManager = injectable

    @route("/login/<string:remote_app>")
    @anonymous_user_required(msg="You are already logged in", category="success")
    def login(self, remote_app):
        provider = getattr(self.oauth, remote_app)
        return provider.authorize(
            callback=url_for(
                "o_auth_controller.authorized",
                remote_app=remote_app,
                _external=True,
                _scheme="https",
            )
        )

    def logout(self):
        session.pop("oauth_token", None)
        self.security_service.logout_user()
        self.flash(_("flask_unchained.bundles.security:flash.logout"), category="success")
        return self.redirect("SECURITY_POST_LOGOUT_REDIRECT_ENDPOINT")

    @route("/authorized/<string:remote_app>")
    @anonymous_user_required(msg="You are already logged in", category="success")
    def authorized(self, remote_app):
        provider = getattr(self.oauth, remote_app)
        resp = provider.authorized_response()
        if resp is None or resp.get("access_token") is None:
            abort(
                HTTPStatus.UNAUTHORIZED,
                "errorCode={error} error={description}".format(
                    error=request.args["error"],
                    description=request.args["error_description"],
                ),
            )

        session["oauth_token"] = resp["access_token"]

        try:
            email, data = self.oauth_service.get_user_details(provider)
        except OAuthEmailError:
            abort(
                HTTPStatus.UNAUTHORIZED,
                "The OAuth provider did not supply a verified email address",
            )
        user, created = self.user_manager.get_or_create(
            email=email, defaults=data, commit=True
        )
        if created:
            self.security_service.register_user(
                user, _force_login_without_confirmation=True
            )
        elif not user.password:
            # the account already exists, but has no local password set, which
            # means it was created by a previous OAuth login - so OAuth is the
            # only way to log in to it
            self.security_service.login_user(user, force=True)
        else:
            # the account already exists and has a local password. the email
            # address asserted by the OAuth provider may be unverified (or the
            # provider itself may be malicious), so it must not be trusted as
            # proof of ownership of an existing password-based account. fail
            # closed instead of force-logging the request into that account.
            abort(
                HTTPStatus.UNAUTHORIZED,
                "This email address is already registered. "
                "Please log in with your email and password.",
            )

        self.oauth_service.on_authorized(provider)
        self.flash(_("flask_unchained.bundles.security:flash.login"), category="success")
        return self.redirect("SECURITY_POST_LOGIN_REDIRECT_ENDPOINT")
