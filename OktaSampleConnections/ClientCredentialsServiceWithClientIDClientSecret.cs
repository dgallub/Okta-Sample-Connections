using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Okta.Sdk;

namespace OktaSampleConnections
{
    public static class ClientCredentialsServiceWithClientIDClientSecret
    {

        public static async Task GetAccessToken()
        {
            Console.WriteLine("Retrieving Access Token for a Service Using Client Credentials w/ Client ID and Client Secret...");

            // Initialize Config Variables
            var clientId = "0oa1x1q9ywwrwjOev5d7";
            var clientSecret = "H_I7VEPzylojqO9tG2HJZym5SgJEiTtOdkGYbbcI";
            var domain = "https://dev-03869058.okta.com";
            var authServerId = "aus1x1mexjbEBVlak5d7";
            var tokenUri = domain + "/oauth2/" + authServerId + "/v1/token";
            var client = new HttpClient();

            using (var request = new HttpRequestMessage(HttpMethod.Post, tokenUri))
            {
                request.Headers.Clear();
                request.Headers.Add("Accept", "application/json");
                request.Headers.Add("Authorization", $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"))}");

                request.Content = new FormUrlEncodedContent(
                    new Dictionary<string, string>()
                    {
                        { "grant_type", "client_credentials" },
                        { "scope", "custom_scope" },
                    }
                );

                // Act
                using (var response = await client.SendAsync(request).ConfigureAwait(false))
                {
                    // Assert
                    response.EnsureSuccessStatusCode();
                    var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    var proto = new
                    {
                        access_token = default(string)
                    };
                    var token = JsonConvert.DeserializeAnonymousType(content, proto).access_token;
                    Console.WriteLine("Done.");
                    Console.WriteLine("\nAccess Token (Not Decoded):\n" + token);
                    var handler = new JwtSecurityTokenHandler();
                    var decodedToken = handler.ReadJwtToken(token);
                    Console.WriteLine("\nAccess Token (Decoded):\n" + decodedToken);
                }
            }
        } 

    }
}
