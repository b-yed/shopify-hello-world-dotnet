using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Shopify_HelloWorld_dotNet.Models
{
    public class WebHookSubscriptionRequest
    {
        public WebHook webhook { get; set; } 
    }

    public class WebHook
    {
        public string topic { get; set; }

        public string address { get; set; }

        public string format { get; set; }
    }
}
