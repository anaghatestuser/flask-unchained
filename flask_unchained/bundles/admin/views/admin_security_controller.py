from http import HTTPStatus

from flask_unchained import lazy_gettext as _
from flask_unchained import request, route
from flask_unchained.bundles.security import SecurityController, current_user


class AdminSecurityController(SecurityController):
    """
    Extends :class:`~flask_unchained.bundles.security.SecurityController`, to
    customize the template folder to use admin-specific templates.
    """

    class Meta:
        template_folder = "admin"

    @route(endpoint="admin.logout", methods=["POST"])
    def logout(self):
        """
        View function to log a user out. Supports html and json requests.

        Logging out changes server-side state, so it requires POST requests;
        when the request is authenticated using the session cookie, a valid
        CSRF token is also required.
        """
        if current_user.is_authenticated:
            self._validate_csrf_token()
            self.security_service.logout_user()

        if request.is_json:
            return "", HTTPStatus.NO_CONTENT

        self.flash(_("flask_unchained.bundles.security:flash.logout"), category="success")
        return self.redirect(
            "ADMIN_POST_LOGOUT_REDIRECT_ENDPOINT",
            "SECURITY_POST_LOGOUT_REDIRECT_ENDPOINT",
        )
