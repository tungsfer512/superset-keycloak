from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from urllib.parse import quote
from flask_appbuilder.views import expose
from flask import request, redirect


class OIDCSecurityManager(SupersetSecurityManager):

    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
        self.authoidview = AuthOIDCView


class AuthOIDCView(AuthOIDView):

    @expose("/login/", methods=["GET", "POST"])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        oidc = sm.oid
        default_role = "Public"

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield("email"))

            if user is None:
                info = oidc.user_getinfo(
                    [
                        "preferred_username",
                        "given_name",
                        "family_name",
                        "email",
                        "resource_access",
                        "realm_access",
                    ]
                )
                print("---------------------------------------")
                print(info)
                superset_roles = (
                    info.get("resource_access").get("superset").get("roles")
                )
                print(superset_roles)
                roles = [role for role in superset_roles]
                print(roles)
                print(oidc.get_cookie_id_token())
                print("---------------------------------------")
                roles += (
                    [
                        default_role,
                    ]
                    if not roles
                    else []
                )
                user = sm.add_user(
                    info.get("preferred_username"),
                    info.get("given_name", ""),
                    info.get("family_name", ""),
                    info.get("email"),
                    [sm.find_role(role) for role in roles],
                )
                user_x = sm.find_user(
                    username=info.get("preferred_username"), email=info.get("email")
                )
                print("+++++++++++++++++++++++++++")
                print(user_x)
                print([sm.find_role(role) for role in roles])
                print("+++++++++++++++++++++++++++")
                print(user)
            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose("/logout/", methods=["GET", "POST"])
    def logout(self):
        oidc = self.appbuilder.sm.oid

        oidc.logout()
        super(AuthOIDCView, self).logout()
        redirect_url = request.url_root.strip("/")
        # redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login

        return (
            redirect(
                oidc.client_secrets.get("issuer")
                + "/protocol/openid-connect/logout?post_logout_redirect_uri="
                + quote(redirect_url)
            )
            + "&id_token_hint="
            + oidc.get_id_token()
        )
