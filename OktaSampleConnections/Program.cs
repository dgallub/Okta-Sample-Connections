using System;
using System.Threading.Tasks;

namespace OktaSampleConnections
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // For Service to Okta APIs Communication
            await ClientCredentialsServiceWithJWKS.GetAccessToken();

            Console.WriteLine("\n---------------------------------\n");

            // For Service to Service Communication
            await ClientCredentialsServiceWithClientIDClientSecret.GetAccessToken();

            Console.WriteLine("\n---------------------------------\n");

            // For OAuth2 Applications without a Secure Back-End
            await AuthorizationCodeFlowWithPKCE.GetTokens(getRefreshToken: false);
            Console.WriteLine("\n---------------------------------\n");
            await AuthorizationCodeFlowWithPKCE.GetTokens(getRefreshToken: true);

            Console.WriteLine("\n---------------------------------\n");

            // For OAuth2 Applications with a Secure Back-End
            await AuthorizationCodeFlowWithClientIDClientSecret.GetTokens(getRefreshToken: false);
            Console.WriteLine("\n---------------------------------\n");
            await AuthorizationCodeFlowWithClientIDClientSecret.GetTokens(getRefreshToken: true);
        }
    }
}
