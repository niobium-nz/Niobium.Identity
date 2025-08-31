using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Niobium.Platform.Identity.API.Functions
{
    public class Authenticate(IAuthenticator authenticator)
    {
        [Function(nameof(Authenticate))]
        public async Task<IActionResult> RunAsync(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = Constants.DefaultIDTokenEndpoint)]
            HttpRequest req,
            CancellationToken cancellationToken)
        {
            return await authenticator.AuthenticateAsync(req, cancellationToken);
        }
    }
}
