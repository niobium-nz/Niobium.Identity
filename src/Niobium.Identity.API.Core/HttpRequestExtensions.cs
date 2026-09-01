using System.Text;
using Microsoft.AspNetCore.Http;
using Niobium.Platform;

namespace Niobium.Identity.API
{
    internal static class HttpRequestExtensions
    {
        public static bool TryGetAuthorizationCredentials(this HttpRequest request, out string scheme, out string identity, out string? credential)
        {
            identity = String.Empty;
            credential = null;

            if (!request.TryParseAuthorizationHeader(out scheme, out string parameter))
            {
                return false;
            }

            scheme = scheme.ToLowerInvariant();
            byte[] base64EncodedBytes = Convert.FromBase64String(parameter);
            string[] credentials = Encoding.UTF8.GetString(base64EncodedBytes).Split(':');
            identity = credentials[0];
            if (credentials.Length >= 2)
            {
                credential = credentials[1];
            }
            return true;
        }
    }
}
