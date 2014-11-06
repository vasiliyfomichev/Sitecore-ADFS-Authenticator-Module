#region

using System;
using System.IdentityModel.Services;
using System.Web;
using Sitecore;

#endregion

namespace ADFS.Authenticator.Authentication
{
    public class WsSessionAuthenticationModule : SessionAuthenticationModule
    {
        #region SessionAuthenticationModule Overrides

        /// <summary>
        /// Initializes the module and prepares it to handle events from the module's ASP.NET application object.
        /// </summary>
        /// <param name="context">The HTTP application object that contains this module.</param>
        protected override void InitializeModule(HttpApplication context)
        {
            context.AuthenticateRequest += OnAuthenticateRequest;
            InitializePropertiesFromConfiguration();
        }

        /// <summary>
        /// Handles the <see cref="E:System.Web.HttpApplication.AuthenticateRequest" /> event from the ASP.NET pipeline.
        /// </summary>
        /// <param name="sender">The source for the event. This will be an <see cref="T:System.Web.HttpApplication" /> object.</param>
        /// <param name="eventArgs">The data for the event.</param>
        protected override void OnAuthenticateRequest(object sender, EventArgs eventArgs)
        {
            if (Context.User != null && Context.User.IsAuthenticated)
                return;
            base.OnAuthenticateRequest(sender, eventArgs);
        }

        #endregion
    }
}