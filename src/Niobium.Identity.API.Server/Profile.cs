using System.Net.Http.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Niobium.Platform;

namespace Niobium.Identity.API.Server
{
    public class Profile(IRepository<Dictionary<string, object>> repo, ProfileServiceAuthorizor authorizor)
    {
        [Function(nameof(GetProfile))]
        public async Task<IActionResult> GetProfile(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = Constants.DefaultProfileEndpoint + "/{tenant}/{user}")] HttpRequest req,
            Guid tenant,
            Guid user,
            CancellationToken cancellationToken)
        {
            if (!req.TryParseAuthorizationHeader(out string inputScheme, out string token)
                || inputScheme != AuthenticationScheme.BearerLoginScheme
                || String.IsNullOrWhiteSpace(token))
            {
                return new UnauthorizedResult();
            }

            bool permissionGrant = await authorizor.CheckPermissionAsync(token, tenant, user, cancellationToken);
            if (!permissionGrant)
            {
                return new BearerForbidResult();
            }

            Dictionary<string, object>? profile = await repo.RetrieveAsync(tenant.ToString(), user.ToString(), cancellationToken: cancellationToken);

            if (profile == null)
            {
                return new NotFoundResult();
            }

            if (profile.TryGetValue(Database.StorageTable.Constants.AzureTableETagKey, out object? etag))
            {
                profile.Add(nameof(EntityKeyKind.ETag), etag);
                profile.Remove(Database.StorageTable.Constants.AzureTableETagKey);
            }

            return new OkObjectResult(profile);
        }

        [Function(nameof(SetProfile))]
        public async Task<IActionResult> SetProfile(
            [HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = Constants.DefaultProfileEndpoint + "/{tenant}/{user}")] HttpRequest req,
            Guid tenant,
            Guid user,
            CancellationToken cancellationToken)
        {
            if (!req.TryParseAuthorizationHeader(out string inputScheme, out string token)
                || inputScheme != AuthenticationScheme.BearerLoginScheme
                || String.IsNullOrWhiteSpace(token))
            {
                return new UnauthorizedResult();
            }

            bool permissionGrant = await authorizor.CheckPermissionAsync(token, tenant, user, cancellationToken);
            if (!permissionGrant)
            {
                return new ForbidResult();
            }

            Dictionary<string, object>? profile = await req.ReadFromJsonAsync<Dictionary<string, object>>(cancellationToken: cancellationToken);
            if (profile == null || profile.Count == 0)
            {
                return new BadRequestResult();
            }

            profile.Remove(nameof(EntityKeyKind.PartitionKey));
            profile.Remove(nameof(EntityKeyKind.RowKey));
            profile.Remove(nameof(EntityKeyKind.Timestamp));
            profile.Add(nameof(EntityKeyKind.PartitionKey), tenant.ToString());
            profile.Add(nameof(EntityKeyKind.RowKey), user.ToString());

            bool preconditionCheck = false;
            if (profile.TryGetValue(nameof(EntityKeyKind.ETag), out object? etag))
            {
                string? eTagStringValue = etag.ToString();
                if (!String.IsNullOrWhiteSpace(eTagStringValue))
                {
                    preconditionCheck = true;

                    // Workaround for ETag as it can be potentially parsed as a JsonElement
                    profile.Remove(nameof(EntityKeyKind.ETag));
                    profile.Add(nameof(EntityKeyKind.ETag), eTagStringValue);
                }
            }

            await repo.UpdateAsync(profile, preconditionCheck: preconditionCheck, mergeIfExists: true, cancellationToken: cancellationToken);

            return new OkResult();
        }
    }
}
