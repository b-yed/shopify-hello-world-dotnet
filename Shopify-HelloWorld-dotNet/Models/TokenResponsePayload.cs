using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Shopify_HelloWorld_dotNet.Models
{
    public class TokenResponsePayload
    {
        public string access_token { get; set; }

        public string scope { get; set; }
    }
}
