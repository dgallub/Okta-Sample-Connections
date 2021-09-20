using IdentityModel;
using Newtonsoft.Json;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace OktaSampleConnections
{
    public static class AuthorizationCodeFlowWithPKCE
    {

        public static async Task GetTokens(bool getRefreshToken)
        {
            if (getRefreshToken)
            {
                Console.WriteLine("Retrieving Access, ID, and Refresh Tokens for an Application Using Authorization Code w/ PKCE...");
            }
            else
            {
                Console.WriteLine("Retrieving Access and ID Tokens for an Application Using Authorization Code w/ PKCE...");
            }

            // Initialize Config Variables
            var domain = "https://dev-03869058.okta.com";
            var authServerId = "aus1x1mexjbEBVlak5d7";
            var clientId = "0oa1x1q9qxGiLGIju5d7";
            var baseUrl = domain + "/oauth2/" + authServerId;
            var username = "test.user@gmail.com";
            var password = "P*ssw0rd1";
            var redirectUri = "http://localhost:8080/login/callback";
            var codeVerifier = CryptoRandom.CreateUniqueId(32);
            var scope = "profile email openid";
            if (getRefreshToken)
            {
                scope += " offline_access";
            }

            Console.WriteLine("Getting Authorization Code...");
            var code = GetAuthorizationCode(baseUrl, clientId, codeVerifier, redirectUri, username, password, scope);
            Console.WriteLine("Done. Authorization Code is: " + code);

            Console.WriteLine("Exchanging Authorization Code for Tokens...");
            var refreshToken = await ExchangeCodeForTokens(baseUrl, code, codeVerifier, redirectUri, clientId);

            if (getRefreshToken)
            {
                Console.WriteLine("Using Refresh Token...");
                await UseRefreshToken(baseUrl, refreshToken, scope, redirectUri, clientId);
            }
        }

        private static string GetAuthorizationCode(string baseUrl, string clientId, string codeVerifier, string redirectUri, string username, string password, string scope)
        {
            var authUri = baseUrl + "/v1/authorize";

            var query = HttpUtility.ParseQueryString(string.Empty);

            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                query["code_challenge"] = Base64Url.Encode(challengeBytes);
                query["code_challenge_method"] = "S256";
            }
            
            query["client_id"] = clientId;
            query["response_type"] = "code";
            query["scope"] = scope;
            query["redirect_uri"] = redirectUri;
            query["state"] = "state";
            var queryString = query.ToString();

            authUri = authUri + "?" + queryString;

            // Replace this with a directory containing a ChromeDriver that matches your Chrome version (mine is 93)
            // Download here: https://chromedriver.chromium.org/downloads
            var driver = new ChromeDriver("C:/Users/David.Gallub/Downloads/chromedriver_win32");
            
            var wait = new WebDriverWait(driver, TimeSpan.FromSeconds(30.00));

            driver.Navigate().GoToUrl(authUri);
            wait.Until(driver1 => (driver.FindElement(By.Name("username")) != null));

            var usernameElement = driver.FindElement(By.Name("username"));
            var passwordElement = driver.FindElement(By.Name("password"));
            var loginButtonElement = driver.FindElement(By.Id("okta-signin-submit"));

            usernameElement.SendKeys(username);
            passwordElement.SendKeys(password);
            loginButtonElement.Click();

            wait.Until(driver1 => driver.Url.Contains(redirectUri));
            var url = driver.Url;
            driver.Close();

            // url?code=insertcodehere&state=insertstatehere
            var splitOne = url.Split("=");
            // ["url?code", "insertcodehere&state", "insertstatehere"]
            var splitTwo = splitOne[1].Split("&");
            // ["insertcodehere", "state"]
            return splitTwo[0];
        }

        private static async Task<string> ExchangeCodeForTokens(string baseUrl, string code, string codeVerifier, string redirectUri, string clientId)
        {
            var tokenUri = baseUrl + "/v1/token";
            var client = new HttpClient();

            using (var request = new HttpRequestMessage(HttpMethod.Post, tokenUri))
            {
                request.Content = new FormUrlEncodedContent(
                    new Dictionary<string, string>()
                    {
                        { "client_id", clientId },
                        { "grant_type", "authorization_code" },
                        { "code", code },
                        { "code_verifier", codeVerifier },
                        { "redirect_uri", redirectUri }
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
                        access_token = default(string),
                        id_token = default(string),
                        refresh_token = default(string)
                    };
                    var tokens = JsonConvert.DeserializeAnonymousType(content, proto);
                    Console.WriteLine("Done.");

                    var accessToken = tokens.access_token;
                    Console.WriteLine("\nAccess Token (Not Decoded):\n" + accessToken);
                    var handler = new JwtSecurityTokenHandler();
                    var decodedAccessToken = handler.ReadJwtToken(accessToken);
                    Console.WriteLine("\nAccess Token (Decoded):\n" + decodedAccessToken);

                    var idToken = tokens.id_token;
                    Console.WriteLine("\nID Token (Not Decoded):\n" + idToken);
                    var decodedIdToken = handler.ReadJwtToken(idToken);
                    Console.WriteLine("\nID Token (Decoded):\n" + decodedIdToken);

                    var refreshToken = tokens.refresh_token;
                    if (!(refreshToken == null))
                    {
                        Console.WriteLine("\nRefresh Token:\n" + refreshToken);
                        return refreshToken;
                    }

                    return null;
                }
            }
        }

        private static async Task UseRefreshToken(string baseUrl, string refreshToken, string scope, string redirectUri, string clientId)
        {
            var tokenUri = baseUrl + "/v1/token";
            var client = new HttpClient();

            using (var request = new HttpRequestMessage(HttpMethod.Post, tokenUri))
            {
                request.Content = new FormUrlEncodedContent(
                    new Dictionary<string, string>()
                    {
                        { "client_id", clientId },
                        { "grant_type", "refresh_token" },
                        { "scope", scope },
                        { "redirect_uri", redirectUri },
                        { "refresh_token", refreshToken }
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
                        access_token = default(string),
                        id_token = default(string),
                        refresh_token = default(string)
                    };
                    var tokens = JsonConvert.DeserializeAnonymousType(content, proto);
                    Console.WriteLine("Done.");

                    var accessToken = tokens.access_token;
                    Console.WriteLine("\nAccess Token (Not Decoded):\n" + accessToken);
                    var handler = new JwtSecurityTokenHandler();
                    var decodedAccessToken = handler.ReadJwtToken(accessToken);
                    Console.WriteLine("\nAccess Token (Decoded):\n" + decodedAccessToken);

                    var idToken = tokens.id_token;
                    Console.WriteLine("\nID Token (Not Decoded):\n" + idToken);
                    var decodedIdToken = handler.ReadJwtToken(idToken);
                    Console.WriteLine("\nID Token (Decoded):\n" + decodedIdToken);

                    var newRefreshToken = tokens.refresh_token;
                    Console.WriteLine("\nRefresh Token:\n" + newRefreshToken);
                }
            }
        }
    }
}
