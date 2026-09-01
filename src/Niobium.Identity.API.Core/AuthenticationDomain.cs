using Niobium.Platform.Identity;

namespace Niobium.Identity.API
{
    internal class AuthenticationDomain(
        Lazy<IRepository<User>> repository,
        IEnumerable<IDomainEventHandler<IDomain<User>>> eventHandlers,
        Lazy<ITokenBuilder> tokenBuilder)
        : GenericDomain<User>(repository, eventHandlers)
    {
        public async Task<string> IssueTokenAsync(Guid appID)
        {
            User entity = await this.GetEntityAsync() ?? throw new ApplicationException(Niobium.InternalError.NotFound);
            return entity.Disabled
                ? throw new ApplicationException(Niobium.InternalError.Locked)
                : await tokenBuilder.Value.BuildAsync(appID, entity.ID.ToKey(), audience: appID.ToString());
        }

        public async Task AuditAsync(string clientIP)
        {
            User entity = await this.GetEntityAsync();
            entity?.LastIP = clientIP;

            await this.SaveAsync();
        }
    }
}
