using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

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
            var apiSecret = _config["ApiSecret"];
            var apiKey = _config["ApiKey"];
            var nonce = CreateNonce();

            var redirectUri = $"{callbackUrl}/shopify/callback";
            var installUri = $"https://{shop}/admin/oauth/authorize?client_id={apiKey}&scope={scopes}&state={nonce}&redirect_uri={redirectUri}";

            HttpContext.Response.Cookies.Append("state", nonce);

            return Redirect(installUri);
        }

        [HttpGet]
        [Route("shopify/callback")]
        public ActionResult Callback([FromQuery] string shop, [FromQuery] string hmac, [FromQuery] string code, [FromQuery] string state)
        {
            var nonce = HttpContext.Request.Cookies["state"];

            if (! state.Equals(nonce))
            {
                return Unauthorized("Request origin cannot be verified");
            }

            return new JsonResult("Hello World, I'm authenticated!");
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
