namespace Cod.Platform.Identity.API
{
    internal class AuthenticationDomain(
        Lazy<IRepository<User>> repository,
        IEnumerable<IDomainEventHandler<IDomain<User>>> eventHandlers,
        Lazy<ITokenBuilder> tokenBuilder)
        : GenericDomain<User>(repository, eventHandlers)
    {
        public async Task<string> IssueTokenAsync(Guid appID)
        {
            User entity = await GetEntityAsync() ?? throw new ApplicationException(InternalError.NotFound);
            if (entity.Disabled)
            {
                throw new ApplicationException(InternalError.Locked);
            }

            return await tokenBuilder.Value.BuildAsync(entity.ID.ToKey(), audience: appID.ToString());
        }

        public async Task AuditAsync(string clientIP)
        {
            User entity = await GetEntityAsync();
            if (entity != null)
            {
                entity.LastIP = clientIP;
            }

            await SaveAsync();
        }
    }
}
