namespace Niobium.Identity.API
{
    internal abstract class OAuthLoginRequestHandler(Lazy<IRepository<Login>> loginRepository, Lazy<IRepository<User>> userRepository)
        : LoginRequestHandler(loginRepository, userRepository), ILoginRequestHandler
    {
        public override bool CanHandle(string scheme, string identity, string? credential) => base.CanHandle(scheme, identity, credential)
                && String.Equals(scheme, AuthenticationScheme.OAuthLoginScheme, StringComparison.OrdinalIgnoreCase)
                && !String.IsNullOrEmpty(credential);

        public override async Task<LoginResult> HandleAsync(string scheme, string identity, string? credential, string? clientIP)
        {
            if (!this.CanHandle(scheme, identity, credential))
            {
                throw new ApplicationException(Niobium.InternalError.BadRequest);
            }

            if (!this.TryParseOAuthParameters(identity, credential, out AuthenticationKind channel, out Guid app, out string? authCode))
            {
                throw new ApplicationException(Niobium.InternalError.BadRequest);
            }

            if (channel == AuthenticationKind.Unknown)
            {
                throw new ApplicationException(Niobium.InternalError.BadRequest);
            }

            string? openID = await this.GetOpenIDAsync(app, authCode);
            if (String.IsNullOrWhiteSpace(openID))
            {
                throw new ApplicationException(Niobium.InternalError.InternalServerError);
            }

            Login? login = await this.LoginRepository.RetrieveAsync(Login.BuildPartitionKey(channel, app.ToKey()), Login.BuildRowKey(openID));
            Guid userID = login?.User ?? await this.SetupNewLoginAsync(channel, app, openID, null, clientIP);

            return new()
            {
                User = userID,
                App = app,
            };
        }

        protected virtual bool TryParseOAuthParameters(string identity, string? credential,
            out AuthenticationKind kind, out Guid app, out string authCode)
        {
            kind = AuthenticationKind.Unknown;
            authCode = String.Empty;
            if (!Guid.TryParse(identity, out app) || credential == null)
            {
                return false;
            }

            string[] parts = credential.Split('@');
            if (parts.Length == 2
                && Enum.TryParse(parts[0], out kind)
                && !String.IsNullOrWhiteSpace(parts[1]))
            {
                authCode = parts[1];
                return true;
            }

            return false;
        }

        protected abstract Task<string?> GetOpenIDAsync(Guid app, string authCode);
    }
}
