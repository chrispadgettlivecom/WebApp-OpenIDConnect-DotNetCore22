using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;

namespace WebApp_OpenIDConnect_DotNetCore22.Controllers
{
    public class HelloController : Controller
    {
        private readonly HttpClient _client;
        private readonly AzureADB2CWithApiOptions _options;

        public HelloController(IOptions<AzureADB2CWithApiOptions> optionsAccessor, HttpClient client)
        {
            _options = optionsAccessor.Value;
            _client = client;
        }

        public async Task<IActionResult> Index()
        {
            string content = "";

            var confidentialClientApplication = ConfidentialClientApplicationBuilder.Create(_options.ClientId)
                .WithClientSecret(_options.ClientSecret)
                .WithB2CAuthority(_options.Authority)
                .WithRedirectUri(_options.RedirectUri)
                .Build();

            var userId = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            var tokenCache = new SessionTokenCache(HttpContext, userId);
            tokenCache.Initialize(confidentialClientApplication.UserTokenCache);
            var accounts = await confidentialClientApplication.GetAccountsAsync();
            var account = accounts.FirstOrDefault();

            var authenticationResult = await confidentialClientApplication.AcquireTokenSilent(_options.ApiScopes.Split(' '), account)
                .ExecuteAsync();

            using (var request = new HttpRequestMessage(HttpMethod.Get, _options.ApiUrl))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authenticationResult.AccessToken);

                using (var response = await _client.SendAsync(request))
                {
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        content = await response.Content.ReadAsStringAsync();
                    }
                    else
                    {
                        content = "Error";
                    }
                }
            }

            ViewData["Content"] = $"{content}";
            return View();
        }
    }
}