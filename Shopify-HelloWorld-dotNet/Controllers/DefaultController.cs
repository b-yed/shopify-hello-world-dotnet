using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Shopify_HelloWorld_dotNet.Models;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Shopify_HelloWorld_dotNet.Controllers
{
    [ApiController]

    public class DefaultController : ControllerBase
    {
        private readonly ILogger<DefaultController> _logger;
        private readonly IConfiguration _config;
        private const string scopes = "read_products";
        private readonly HttpClient _client;

        public DefaultController(ILogger<DefaultController> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;
            _client = new HttpClient();
        }

        [HttpGet]
        [Route("/")]
        public ActionResult Callback()
        {
           return new JsonResult("Hello World");
        }

        [HttpGet]
        [Route("shopify")]
        public ActionResult Install([FromQuery] string shop)
        {
            var callbackUrl = _config["CallbackUrl"];
            var apiKey = _config["ApiKey"];
            var nonce = CreateNonce();

            var redirectUri = $"{callbackUrl}/shopify/callback";
            var installUri = $"https://{shop}/admin/oauth/authorize?client_id={apiKey}&scope={scopes}&state={nonce}&redirect_uri={redirectUri}";

            HttpContext.Response.Cookies.Append("state", nonce);

            return Redirect(installUri);
        }

        [HttpGet]
        [Route("shopify/callback")]
        public async Task<ActionResult> Callback([FromQuery] string shop, [FromQuery] string hmac, [FromQuery] string code, [FromQuery] string state)
        {
            var nonce = HttpContext.Request.Cookies["state"];

            if (! state.Equals(nonce))
            {
                return Unauthorized("Request origin cannot be verified");
            }

            var apiSecret = _config["ApiSecret"];
            var apiKey = _config["ApiKey"];

            //TODO - Validate hmac

            //Get an access token
            var response = await _client.PostAsync($"https://{shop}/admin/oauth/access_token", new StringContent(
                JsonSerializer.Serialize<TokenRequestPayload>(new TokenRequestPayload() { 
                client_id = apiKey,
                client_secret = apiSecret,
                code = code
            }), Encoding.UTF8, "application/json"));

            if (response.IsSuccessStatusCode)
            {
                var responseData = JsonSerializer.Deserialize<TokenResponsePayload>(await response.Content.ReadAsStringAsync());

                return new JsonResult(await GetShopDataAsync(responseData.access_token, shop));
            }

            return new JsonResult("Something went wrong!");
        }

        private async Task<string> GetShopDataAsync(string accessToken, string shop)
        {
            using (var requestMessage =
            new HttpRequestMessage(HttpMethod.Get, $"https://{shop}/admin/api/2020-04/shop.json"))
            {
                requestMessage.Headers.TryAddWithoutValidation("X-Shopify-Access-Token", accessToken);
                var response = await _client.SendAsync(requestMessage);

                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadAsStringAsync();
                }
            }

            return string.Empty;
        }

        private string CreateNonce()
        {
            var ByteArray = new byte[20];
            using (var Rnd = RandomNumberGenerator.Create())
            {
                Rnd.GetBytes(ByteArray);
            }
            return Convert.ToBase64String(ByteArray);
        }
    }
}
