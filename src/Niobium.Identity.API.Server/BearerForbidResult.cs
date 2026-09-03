using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Niobium.Identity.API.Server
{
    internal sealed class BearerForbidResult : IActionResult
    {
        private readonly object? _value;

        // Constructor for an empty 403 response
        public BearerForbidResult() { }

        // Constructor if you want to pass a JSON error payload
        public BearerForbidResult(object? value) => this._value = value;

        public async Task ExecuteResultAsync(ActionContext context)
        {
            HttpResponse response = context.HttpContext.Response;

            // 1. Set the status code to 403 Forbidden
            response.StatusCode = StatusCodes.Status403Forbidden;

            // 2. Append the WWW-Authenticate header
            response.Headers.Append("WWW-Authenticate", AuthenticationScheme.BearerLoginScheme);

            // 3. Write the body payload if one was provided
            if (this._value != null)
            {
                var objectResult = new ObjectResult(this._value);
                await objectResult.ExecuteResultAsync(context);
            }
        }
    }
}
