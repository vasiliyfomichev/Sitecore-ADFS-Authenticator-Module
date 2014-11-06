#region

using System.Collections.Specialized;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Web;
using System.Web.Security;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Security.Accounts;
using Sitecore.Security.Authentication;
using Sitecore.Shell.Applications.ContentEditor;

#endregion

namespace ADFS.Authenticator.Authentication
{
    public class FederatedAuthenticationProvider : MembershipAuthenticationProvider
    {
        #region Fields

        private AuthenticationHelper _helper;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the helper object.
        /// </summary>
        /// <value>
        /// The helper.
        /// </value>
        protected override Sitecore.Security.Authentication.AuthenticationHelper Helper
        {
            get
            {
                var authenticationHelper = _helper;
                Assert.IsNotNull(authenticationHelper, "AuthenticationHelper has not been set. It must be set in Initialize.");
                return authenticationHelper;
            }
        }

        #endregion

        #region MembershipAuthenticationProvider Overrides

        /// <summary>
        /// Initializes the provider.
        /// </summary>
        /// <param name="name">The friendly name of the provider.</param>
        /// <param name="config">A collection of the name/value pairs representing the provider-specific attributes specified in the configuration for this provider.</param>
        public override void Initialize(string name, NameValueCollection config)
        {
            Assert.ArgumentNotNullOrEmpty(name, "name");
            Assert.ArgumentNotNull(config, "config");

            base.Initialize(name, config);
            _helper = new AuthenticationHelper(this);
        }

        /// <summary>
        /// Gets the active user.
        /// </summary>
        /// <returns>
        /// Active User.
        /// </returns>
        public override User GetActiveUser()
        {
            var activeUser = this.Helper.GetActiveUser();
            Assert.IsNotNull(activeUser, "Active user cannot be empty.");
            return activeUser;
        }

        /// <summary>
        /// Logs the specified user into the system without checking password.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="persistent">If set to <c>true</c> (and the provider supports it), the login will be persisted.</param>
        /// <returns></returns>
        public override bool Login(string userName, bool persistent)
        {
            Assert.ArgumentNotNullOrEmpty(userName, "userName");
            if (!base.Login(userName, persistent))
                return false;
            SessionSecurityToken sessionToken;
            if (!FederatedAuthentication.SessionAuthenticationModule.TryReadSessionTokenFromCookie(out sessionToken))
                FormsAuthentication.SetAuthCookie(userName, persistent);
            return true;
        }

        /// <summary>
        /// Logs in the specified user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns></returns>
        public override bool Login(User user)
        {
            Assert.ArgumentNotNull(user, "user");
            if (!base.Login(user))
                return false;

            SessionSecurityToken sessionToken;
            if (!FederatedAuthentication.SessionAuthenticationModule.TryReadSessionTokenFromCookie(out sessionToken))
                FormsAuthentication.SetAuthCookie(user.Name, false);
            StoreMetaData(user);
            return true;
        }

        /// <summary>
        /// Logs out the current user.
        /// </summary>
        public override void Logout()
        {
            base.Logout();
            RecentDocuments.Remove();
            SessionSecurityToken sessionToken;
            if (!FederatedAuthentication.SessionAuthenticationModule.TryReadSessionTokenFromCookie(out sessionToken))
            {
                FormsAuthentication.SignOut();
                ClearFormCookies();
            }
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
        }

        /// <summary>
        /// Sets the active user.
        /// </summary>
        /// <param name="user">The user object.</param>
        public override void SetActiveUser(User user)
        {
            Helper.SetActiveUser(user);
        }

        /// <summary>
        /// Sets the active user.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        public override void SetActiveUser(string userName)
        {
            Assert.ArgumentNotNullOrEmpty(userName, "userName");
            Helper.SetActiveUser(userName);
        }

        #endregion

        #region Methods

        /// <summary>
        /// Stores the meta data.
        /// </summary>
        /// <param name="user">The user.</param>
        private static void StoreMetaData(User user)
        {
            var runtimeSettings = user.RuntimeSettings;
            if (!runtimeSettings.IsVirtual)
                return;
            ClientContext.SetValue("SC_USR_" + user.Name, runtimeSettings.Serialize());
        }

        /// <summary>
        /// Clears the form cookies.
        /// </summary>
        private static void ClearFormCookies()
        {
            var context = HttpContext.Current;
            if (context == null || context.Request.Browser == null)
                return;
            var strB = string.Empty;
            if (context.Request.Browser["supportsEmptyStringInCookieValue"] == "false")
                strB = "NoCookie";
            if (context.Request.Cookies[FormsAuthentication.FormsCookieName] != null && string.Compare(context.Request.Cookies[FormsAuthentication.FormsCookieName].Value, strB, System.StringComparison.OrdinalIgnoreCase) != 0)
                context.Request.Cookies[FormsAuthentication.FormsCookieName].Value = strB;
        }

        #endregion
    }
}