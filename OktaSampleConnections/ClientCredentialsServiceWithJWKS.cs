using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Newtonsoft.Json;
using Okta.Sdk;
using Okta.Sdk.Configuration;
using Okta.Sdk.Internal;

namespace OktaSampleConnections
{
    public static class ClientCredentialsServiceWithJWKS
    {

        public static async Task GetAccessToken()
        {
            Console.WriteLine("Retrieving Access Token for a Service Using Client Credentials w/ JWKS...");

            // Initialize Okta Configuration Variables
            var domain = "https://dev-03869058.okta.com/";
            var clientId = "0oa1x23sreyLMNBjq5d7";
            var scopes = new List<string> { "okta.groups.manage", "okta.users.manage" };
            var dict = GetLocalFile("jwks.json");

            // Create OktaClient
            var config = new OktaClientConfiguration
            {
                OktaDomain = domain,
                AuthorizationMode = AuthorizationMode.PrivateKey,
                ClientId = clientId,
                Scopes = scopes,
                PrivateKey = new JsonWebKeyConfiguration(dict["jwk"].ToString())
            };
            var oktaClient = new OktaClient(config);

            // Get Access Token Using ResourceFactory and DefaultOAuthTokenProvider
            var resourceFactory = new ResourceFactory(oktaClient, NullLogger.Instance);
            var p = new DefaultOAuthTokenProvider(config, resourceFactory);
            var token = await p.GetAccessTokenAsync().ConfigureAwait(false);
            Console.WriteLine("Done.");
            Console.WriteLine("\nAccess Token (Not Decoded):\n" + token);
            var handler = new JwtSecurityTokenHandler();
            var decodedToken = handler.ReadJwtToken(token);
            Console.WriteLine("\nAccess Token (Decoded):\n" + decodedToken);


            // Use Access Token to Make API Call(s)
            Console.WriteLine("\nMaking GET request to Okta Users API...");
            using (var request = new HttpRequestMessage(HttpMethod.Get, domain + "api/v1/users"))
            {
                request.Headers.Clear();
                request.Headers.Add("Accept", "application/json");
                request.Headers.Add("Authorization", "Bearer " + token);

                // Send the request
                var client = new HttpClient();
                using (var response = await client.SendAsync(request).ConfigureAwait(false))
                {
                    response.EnsureSuccessStatusCode();
                    var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    Console.WriteLine("\nResponse:\n" + content);
                }
            }
        }

        /// <summary>
        /// Downloads a JSON file and returns a dictionary of the parsed content.
        /// </summary>
        /// <param name="uri"></param>
        /// <returns></returns>
        private static Dictionary<string, object> GetLocalFile(String path)
        {
            using (var stream = File.OpenRead(path))
            using (var textReader = new StreamReader(stream))
            using (var reader = new JsonTextReader(textReader))
            {
                return JsonSerializer.CreateDefault().Deserialize<Dictionary<string, object>>(reader);
            }
        }

    }
}
