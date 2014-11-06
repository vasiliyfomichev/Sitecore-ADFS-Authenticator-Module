#region

using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using Sitecore;
using Sitecore.Diagnostics;
using Sitecore.Pipelines.HttpRequest;

#endregion

namespace ADFS.Authenticator.Pipelines.HttpRequest
{
    public class TokenRequestor : HttpRequestProcessor
    {
        /// <summary>
        /// Gets the ADFS token.
        /// </summary>
        /// <param name="args">The args.</param>
        public override void Process(HttpRequestArgs args)
        {
            if (Context.User != null && Context.User.IsAuthenticated)
                return;

            Assert.ArgumentNotNull(args, "args");

            SessionSecurityToken sessionToken = null;
            FederatedAuthentication.SessionAuthenticationModule.TryReadSessionTokenFromCookie(out sessionToken);
            if (sessionToken != null)
                FederatedAuthentication.SessionAuthenticationModule.AuthenticateSessionSecurityToken(sessionToken, false);
            if (!args.PermissionDenied && (sessionToken == null || string.IsNullOrEmpty(sessionToken.Id)))
                return;
            LoginHelper.RequestToken();
        }
    }
}