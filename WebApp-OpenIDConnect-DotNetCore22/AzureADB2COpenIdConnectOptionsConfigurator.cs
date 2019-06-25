using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebApp_OpenIDConnect_DotNetCore22
{
    public class AzureADB2COpenIdConnectOptionsConfigurator : IConfigureNamedOptions<OpenIdConnectOptions>
    {
        private readonly AzureADB2CWithApiOptions _options;

        public AzureADB2COpenIdConnectOptionsConfigurator(IOptions<AzureADB2CWithApiOptions> optionsAccessor)
        {
            _options = optionsAccessor.Value;
        }

        public void Configure(string name, OpenIdConnectOptions options)
        {
            options.Events.OnAuthorizationCodeReceived = WrapOpenIdConnectEvent(options.Events.OnAuthorizationCodeReceived, OnAuthorizationCodeReceived);
            options.Events.OnRedirectToIdentityProvider = WrapOpenIdConnectEvent(options.Events.OnRedirectToIdentityProvider, OnRedirectToIdentityProvider);
        }

        public void Configure(OpenIdConnectOptions options)
        {
            Configure(Options.DefaultName, options);
        }

        private static Func<TContext, Task> WrapOpenIdConnectEvent<TContext>(Func<TContext, Task> baseEventHandler, Func<TContext, Task> thisEventHandler)
        {
            return new Func<TContext, Task>(async context =>
            {
                await baseEventHandler(context);
                await thisEventHandler(context);
            });
        }

        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
        {
            var confidentialClientApplication = ConfidentialClientApplicationBuilder.Create(context.Options.ClientId)
                .WithClientSecret(context.Options.ClientSecret)
                .WithB2CAuthority(context.Options.Authority)
                .WithRedirectUri(_options.RedirectUri)
                .Build();

            var userId = context.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
            var tokenCache = new SessionTokenCache(context.HttpContext, userId);
            tokenCache.Initialize(confidentialClientApplication.UserTokenCache);

            try
            {
                var authenticationResult = await confidentialClientApplication.AcquireTokenByAuthorizationCode(_options.ApiScopes.Split(' '), context.ProtocolMessage.Code)
                    .ExecuteAsync();

                context.HandleCodeRedemption(authenticationResult.AccessToken, authenticationResult.IdToken);
            }
            catch (Exception ex)
            {
                // TODO: Handle
                throw;
            }
        }

        private Task OnRedirectToIdentityProvider(RedirectContext context)
        {
            context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.CodeIdToken;
            context.ProtocolMessage.Scope += $" offline_access {_options.ApiScopes}";
            return Task.FromResult(0);
        }
    }
}
