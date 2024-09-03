using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Cod.Platform.Identity.API
{
    public interface IAuthenticator
    {
        Task<IActionResult> AuthenticateAsync(HttpRequest req, CancellationToken cancellationToken);
    }
}
