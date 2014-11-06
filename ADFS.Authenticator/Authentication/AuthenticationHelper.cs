#region

using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Threading;
using System.Web;
using Sitecore;
using Sitecore.Diagnostics;
using Sitecore.Security.Accounts;
using Sitecore.Security.Authentication;

#endregion

namespace ADFS.Authenticator.Authentication
{
    public class AuthenticationHelper : Sitecore.Security.Authentication.AuthenticationHelper
    {
        #region Constructor

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationHelper"/> class.
        /// </summary>
        /// <param name="provider">The provider.</param>
        public AuthenticationHelper(AuthenticationProvider provider)
            : base(provider)
        {
        }

        #endregion

        #region AuthenticationHelper Overrides

        /// <summary>
        /// Sets the active user.
        /// </summary>
        /// <param name="user">The user object.</param>
        public override void SetActiveUser(User user)
        {
            Assert.ArgumentNotNull(user, "user");

            var name = user.Name;
            if (!name.Contains("\\"))
                Globalize(Context.Domain.Name, name);
            base.SetActiveUser(user);
        }

        /// <summary>
        /// Sets the active user.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        public override void SetActiveUser(string userName)
        {
            Assert.ArgumentNotNull(userName, "userName");
            var userName1 = userName;
            if (!userName1.Contains("\\"))
                Globalize(Context.Domain.Name, userName1);
            base.SetActiveUser(userName);
        }

        #endregion

        #region Methods

        /// <summary>
        /// Determines whether the specified user is disabled.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns></returns>
        protected virtual bool IsDisabled(User user)
        {
            Assert.ArgumentNotNull(user, "user");

            return !user.Profile.IsAnonymous && user.Profile.State.Contains("Disabled");
        }

        /// <summary>
        /// Gets the current user.
        /// </summary>
        /// <returns>
        /// The current user; <c>null</c> if user is not defined (anonymous).
        /// </returns>
        protected new virtual User GetCurrentUser()
        {
            var current = HttpContext.Current;
            if (current != null)
            {
                if (current.User != null)
                    return null;
                SessionSecurityToken sessionToken;
                FederatedAuthentication.SessionAuthenticationModule.TryReadSessionTokenFromCookie(out sessionToken);
                if (sessionToken != null && sessionToken.ClaimsPrincipal != null)
                {
                    var identity = sessionToken.ClaimsPrincipal.Identity;
                    if (!string.IsNullOrEmpty(identity.Name) && User.Exists(Globalize(Context.Domain.Name, identity.Name)))
                        return AuthenticationHelper.GetUser(Globalize(Context.Domain.Name, identity.Name), true);
                }
                return base.GetCurrentUser();
            }
            else
            {
                if (Thread.CurrentPrincipal != null)
                {
                    if (Thread.CurrentPrincipal is User)
                        return Thread.CurrentPrincipal as User;
                    if (!string.IsNullOrEmpty(Thread.CurrentPrincipal.Identity.Name))
                        return AuthenticationHelper.GetUser(Thread.CurrentPrincipal.Identity.Name, Thread.CurrentPrincipal.Identity.IsAuthenticated);
                }
                return null;
            }
        }

        /// <summary>
        /// Gets the user.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="isAuthenticated">if set to <c>true</c> [is authenticated].</param>
        /// <returns></returns>
        private static User GetUser(string userName, bool isAuthenticated)
        {
            Assert.ArgumentNotNull(userName, "userName");

            return User.FromName(userName, isAuthenticated);
        }

        /// <summary>
        /// Globalizes the specified user in specified domain name.
        /// </summary>
        /// <param name="domainName">Name of the domain.</param>
        /// <param name="userName">Name of the user.</param>
        /// <returns></returns>
        private static string Globalize(string domainName, string userName)
        {
            var str = userName;
            if (!userName.StartsWith(domainName + "\\"))
                str = domainName + "\\" + userName;
            return str;
        }

        #endregion
    }
}