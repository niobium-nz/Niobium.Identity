using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Niobium.Platform.Identity.API
{
    public interface IAuthenticator
    {
        Task<IActionResult> AuthenticateAsync(HttpRequest req, CancellationToken cancellationToken);
    }
}
