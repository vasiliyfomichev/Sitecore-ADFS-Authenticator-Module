#region

using System;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Security.Principal;
using System.Web;
using Sitecore;
using Sitecore.Diagnostics;
using Sitecore.Pipelines.HttpRequest;
using Sitecore.Security.Authentication;

#endregion

namespace ADFS.Authenticator.Pipelines.HttpRequest
{
    public class UserResolver : Sitecore.Pipelines.HttpRequest.UserResolver
    {
        /// <summary>
        /// Sets the virtual user from the ADFS token.
        /// </summary>
        /// <param name="args">The arguments.</param>
        public override void Process(HttpRequestArgs args)
        {
            AuthenticationManager.GetActiveUser();
            if (Context.User != null && Context.User.IsAuthenticated)
                return;
            try
            {
                SessionSecurityToken sessionToken = null;
                FederatedAuthentication.SessionAuthenticationModule.TryReadSessionTokenFromCookie(out sessionToken);
                if (sessionToken != null)
                {
                    try
                    {
                        FederatedAuthentication.SessionAuthenticationModule.AuthenticateSessionSecurityToken(
                            sessionToken, true);
                    }
                    catch
                    {
                        FederatedAuthentication.WSFederationAuthenticationModule.SignOut(false);
                        LoginHelper.RequestToken();
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error("ADFS::Error parsing token", ex, (object)this);
                return;
            }
            IPrincipal user = HttpContext.Current.User;
            if (user != null)
                new LoginHelper().Login(user);
        }
    }
}