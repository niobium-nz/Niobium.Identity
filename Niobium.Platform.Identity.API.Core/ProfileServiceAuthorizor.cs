using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http.Json;
using System.Security.Claims;

namespace Niobium.Platform.Identity.API
{
    public class ProfileServiceAuthorizor(
        PrincipalParser principalParser,
        IHttpClientFactory httpClientFactory,
        IOptions<IdentityAPIOptions> options,
        ILogger<Profile> logger)
    {
        private static readonly SemaphoreSlim signingKeysLock = new(1, 1);
        private static JsonWebKeySet? signingKeys;
        private const string AudienceClaim = "aud";

        public async Task<bool> CheckPermissionAsync(string token, Guid tenant, Guid user, CancellationToken cancellationToken)
        {
            bool result = await CheckClientTokenAsync(token, tenant, user, cancellationToken);
            return result || await CheckServicePrincipalAsync(token, tenant, user, cancellationToken);
        }

        private async Task<bool> CheckClientTokenAsync(string token, Guid tenant, Guid user, CancellationToken cancellationToken)
        {
            try
            {
                ClaimsPrincipal principal = await principalParser.ParseIDPrincipalAsync(token, null, cancellationToken);
                if (principal == null)
                {
                    return false;
                }

                return principal.TryGetClaim<Guid>(ClaimTypes.NameIdentifier, out Guid u) && u == user && principal.TryGetClaim<Guid>(AudienceClaim, out Guid t) && t == tenant;
            }
            catch (Exception e)
            {
                logger.LogError(e, $"An exception occurred during client token validation: {e.Message}");
                return false;
            }
        }

        private async Task<bool> CheckServicePrincipalAsync(string token, Guid tenant, Guid user, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(options.Value.TenantID) || string.IsNullOrWhiteSpace(options.Value.ApplicationID))
            {
                return false;
            }

            JsonWebKeySet keys = await GetSigningKeysAsync(tenant, cancellationToken);
            TokenValidationParameters validationParameters = new()
            {
                IssuerSigningKeys = keys.Keys,
                ValidateIssuer = true,
                ValidIssuer = $"https://sts.windows.net/{options.Value.TenantID}/",
                ValidateAudience = true,
                ValidAudience = $"api://{options.Value.ApplicationID}",
                ValidateLifetime = true,
            };

            JsonWebTokenHandler handler = new();
            try
            {
                TokenValidationResult validationResult = await handler.ValidateTokenAsync(token, validationParameters);

                if (validationResult.IsValid)
                {
                    return true;
                }
                else
                {
                    logger.LogError($"Token validation failed: {validationResult.Exception?.Message}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"An exception occurred during service principal token validation: {ex.Message}");
                return false;
            }
        }

        private async Task<JsonWebKeySet> GetSigningKeysAsync(Guid tenant, CancellationToken cancellationToken)
        {
            if (signingKeys != null)
            {
                return signingKeys;
            }

            await signingKeysLock.WaitAsync(cancellationToken);
            try
            {
                if (signingKeys == null)
                {
                    HttpClient httpClient = httpClientFactory.CreateClient(Constants.DefaultHttpClientName);
                    signingKeys = await httpClient.GetFromJsonAsync<JsonWebKeySet>($"/{tenant}/discovery/keys", cancellationToken: cancellationToken)
                        ?? throw new ApplicationException(InternalError.InternalServerError, "Failed to retrieve signing keys.");
                }
            }
            finally
            {
                signingKeysLock.Release();
            }

            return signingKeys;
        }
    }
}
