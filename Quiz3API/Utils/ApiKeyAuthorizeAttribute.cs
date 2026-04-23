using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Quiz3API.Models;

namespace Quiz3API.Utils
{
    public class APIKeyAuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<APIKeyAuthorizeAttribute>>();

            var configuration = context.HttpContext.RequestServices.GetService(typeof(IConfiguration)) as IConfiguration;

            if (!context.HttpContext.Request.Headers.TryGetValue("X-API-KEY", out var extractedApiKey))
            {
                logger.LogWarning("Invalid API Key attempt from IP {IP}", context.HttpContext.Connection.RemoteIpAddress);
                context.Result = new ContentResult()
                {
                    StatusCode = 401,
                    Content = "API Key was not provided."
                };
                return;
            }

            //if (configuration == null || string.IsNullOrEmpty(configuration["Security:ApiKey"])) **ONLY FOR SINGULAR API KEY**
            //{
            //    context.Result = new ContentResult()
            //    {
            //        StatusCode = 500,
            //        Content = "Server configuration error: API Key not found."
            //    };
            //    return;
            //}

            //var apiKey = configuration["Security:ApiKey"]; **ONLY FOR SINGULAR API KEY**

            //if (!apiKey.Equals(extractedApiKey))
            //{
            //    context.Result = new ContentResult()
            //    {
            //        StatusCode = 401,
            //        Content = "Invalid API Key."
            //    };
            //    return;
            //}

            if (configuration == null)
            {
                logger.LogWarning("Server configuration error: API Key not found.");
                context.Result = new ContentResult()
                {
                    StatusCode = 500,
                    Content = "Server configuration error: API Key not found."
                };
                return;
            }

            //var validKeys = configuration.GetSection("Security:ApiKey").Get<List<string>>(); // this is for getting multiple API keys from the configuration

            //if (validKeys == null || validKeys.Count() == 0)
            //{
            //    context.Result = new ContentResult()
            //    {
            //        StatusCode = 500,
            //        Content = "Server configuration error: API Keys not found."
            //    };
            //    return;
            //}

            //if (!validKeys.Contains(extractedApiKey)) //checking if the extracted API key is in the list of valid API keys
            //{
            //    context.Result = new ContentResult()
            //    {
            //        StatusCode = 401,
            //        Content = "Invalid API Key."
            //    };
            //    return;
            //}

            //if (extractedApiKey == "SARMIENTOKEY") //for disabling a certain API key
            //{
            //    context.Result = new ContentResult()
            //    {
            //        StatusCode = 401,
            //        Content = "APIKey is disabled"
            //    };
            //    return;
            //}

            //for keys with expiration
            var validKeys = configuration.GetSection("Security:ApiKeyExpiration").Get<List<ApiKeyConfig>>();

            var matchedKey = validKeys?.FirstOrDefault(x => x.Key == extractedApiKey);

            if (matchedKey == null) //if di nahanap si key sa list ng valid keys na objects
            {
                logger.LogWarning("API Key is Invalid");
                context.Result = new ContentResult()
                {
                    StatusCode = 401,
                    Content = "API Key is Invalid"
                };
                return;
            }

            if (matchedKey.ExpiresAt < DateTime.UtcNow) //if expired na yung key
            {
                logger.LogWarning("API Key has expired");
                context.Result = new ContentResult()
                {
                    StatusCode = 403,
                    Content = "API Key has expired"
                };
                return;
            }
        }
    }
}
