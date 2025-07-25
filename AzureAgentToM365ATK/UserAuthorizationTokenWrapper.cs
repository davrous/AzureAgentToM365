using Azure.Core;
using Microsoft.Agents.Builder;
using Microsoft.Agents.Builder.App.UserAuth;
using System.IdentityModel.Tokens.Jwt;

namespace AzureAgentToM365ATK
{
    /// <summary>
    /// This class wraps the UserAuthorization to provide a TokenCredential implementation as the AI Foundry agent expects a TokenCredential to be used for authentication.
    /// Note to be able to authenticate with the AI Foundry agent, the application that was used to create the user JWT token must have the 'Azure Machine Learning Services' => 'user_impersonation' scope configured in the Azure portal.
    /// </summary>
    public class UserAuthorizationTokenWrapper : TokenCredential
    {
        private readonly UserAuthorization _userAuthorization;
        private readonly string _handlerName;
        private readonly ITurnContext _turnContext;
        public UserAuthorizationTokenWrapper(UserAuthorization userAuthorization, ITurnContext turnContext, string handlerName)
        {
            _userAuthorization = userAuthorization;
            _handlerName = handlerName ?? throw new ArgumentNullException(nameof(handlerName));
            _turnContext = turnContext ?? throw new ArgumentNullException(nameof(turnContext));
        }

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
#pragma warning disable CA2012
            return GetTokenAsync(requestContext, cancellationToken).Result;
#pragma warning restore CA2012
        }

        /// <summary>
        /// This method exchanges the current user's turn token for a JWT token that can be used to authenticate with the AI Foundry agent.
        /// </summary>
        /// <param name="requestContext"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            // We need to handle converting .default scope to User_Impersonation scope.  
            // this is a compensation for AI Foundry not yet publishing an application that contains the .default scope for the AI endpoint.
            List<string> scp = new();
            foreach (var scope in requestContext.Scopes)
            {
                if (scope.Contains(".default" , StringComparison.OrdinalIgnoreCase))
                    scp.Add(scope.Replace(".default", "user_impersonation", StringComparison.OrdinalIgnoreCase));
                else
                    scp.Add(scope);
            }

            // Exchange the turn token for a JWT token for AI Foundry using the UserAuthorization service.
            var jwtToken = await _userAuthorization.ExchangeTurnTokenAsync(_turnContext, exchangeScopes: scp, handlerName: _handlerName, cancellationToken: cancellationToken).ConfigureAwait(false);

            // Convert the JWT token to a Azure AccessToken.
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(jwtToken);
            long? expClaim = jwt.Payload.Expiration;
            if (expClaim == null)
                throw new InvalidOperationException("JWT does not contain an 'exp' claim.");
            var expiresOn = DateTimeOffset.FromUnixTimeSeconds((long)expClaim);

            return new AccessToken(jwtToken, expiresOn);
        }

    }
}
