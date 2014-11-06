#region

using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using Sitecore;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Security.Accounts;
using Sitecore.Security.Authentication;
using Sitecore.Web;

#endregion

namespace ADFS.Authenticator.Pipelines.HttpRequest
{
    public class LoginHelper
    {
        /// <summary>
        /// Logins the specified user.
        /// </summary>
        /// <param name="user">The user.</param>
        public void Login(IPrincipal user)
        {
            var identity = user.Identity;

#if DEBUG
            WriteClaimsInfo(user.Identity as ClaimsIdentity);
#endif
            if (!identity.IsAuthenticated)
                return;
            var userName = string.Format("{0}\\{1}", Context.Domain.Name, identity.Name);
            try
            {
                var virtualUser = AuthenticationManager.BuildVirtualUser(userName, true);
                var roles = Context.Domain.GetRoles();
                if (roles != null)
                {
                    var groups = GetGroups(user.Identity as ClaimsIdentity);
                    foreach (var role in from role in roles
                                         let roleName = GetRoleName(role.Name)
                                         where groups.Contains(roleName.ToLower()) && !virtualUser.Roles.Contains(role)
                                         select role)
                    {
                        virtualUser.Roles.Add(role);
                    }
                    foreach (
                        var role2 in
                            virtualUser.Roles.SelectMany(
                                role1 =>
                                    RolesInRolesManager.GetRolesForRole(role1, true)
                                        .Where(role2 => !virtualUser.Roles.Contains(role2))))
                    {
                        virtualUser.Roles.Add(role2);
                    }

                    // Setting the user to be an admin.
                    virtualUser.RuntimeSettings.IsAdministrator =
                        groups.Contains(Settings.GetSetting("ADFS.Authenticator.AdminUserRole", "Admins"));
                }

                AuthenticationManager.Login(virtualUser);
            }
            catch (ArgumentException ex)
            {
                Log.Error("ADFS::Login Failed!", ex, this);
            }
        }

        /// <summary>
        /// Gets the group names.
        /// </summary>
        /// <param name="claimsIdentity">The claims identity.</param>
        /// <returns></returns>
        private static IEnumerable<string> GetGroups(ClaimsIdentity claimsIdentity)
        {
            var enumerable =
                claimsIdentity.Claims.Where(
                    c => c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role").ToList();
            var list = new List<string>();
            foreach (
                var str in
                    enumerable.Select(claim => claim.Value.ToLower().Replace('-', '_'))
                        .Where(str => !list.Contains(str)))
            {
                list.Add(str);
            }
            return list.ToArray();
        }

        /// <summary>
        /// Gets the name of the role.
        /// </summary>
        /// <param name="roleName">Name of the role.</param>
        /// <returns></returns>
        private static string GetRoleName(string roleName)
        {
            if (!roleName.Contains('\\'))
                return roleName;
            return roleName.Split(new[]
            {
                '\\'
            })[1];
        }

        /// <summary>
        /// Requests the token.
        /// </summary>
        public static void RequestToken()
        {
            var url =
                FederatedAuthentication.WSFederationAuthenticationModule.CreateSignInRequest(Guid.NewGuid().ToString(),
                    HttpContext.Current.Request.RawUrl, false).WriteQueryString();
            if (string.IsNullOrWhiteSpace(url))
                return;

            WebUtil.Redirect(url);
        }

        /// <summary>
        /// Writes the claims information.
        /// </summary>
        /// <param name="claimsIdentity">The claims identity.</param>
        private void WriteClaimsInfo(ClaimsIdentity claimsIdentity)
        {
            Log.Info("Writing Claims Info", this);
            foreach (var claim in claimsIdentity.Claims)
                Log.Info(string.Format("Claim : {0} , {1}", claim.Type, claim.Value), this);
        }

        /// <summary>
        /// Adds the claims information.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="claimsIdentity">The claims identity.</param>
        public void AddClaimsInfo(User user, ClaimsIdentity claimsIdentity)
        {
        }
    }
}