using System.Security.Cryptography;
using System.Text;

namespace Cod.Platform.Identity.API
{
    internal class PasswordLoginRequestHandler(Lazy<IRepository<Login>> repository, IConfigurationProvider configuration) : ILoginRequestHandler
    {
        public const string PASSWORD_LOGIN_CREDENTIAL_PREFIX = "PIN:";
        public const string SETTING_PASSWORD_HASH_KEY = "PASSWORD_HASH_KEY";

        public bool CanHandle(string scheme, string identity, string? credential)
            => string.Equals(scheme, AuthenticationScheme.BasicLoginScheme, StringComparison.InvariantCultureIgnoreCase)
                && TryParseCredential(credential, out _)
                && IdentityHelper.TryParseTenantAndUserName(identity, out _, out _);

        public async Task<LoginResult> HandleAsync(string scheme, string identity, string? credential, string clientIP)
        {
            if (!CanHandle(scheme, identity, credential))
            {
                throw new ApplicationException(InternalError.BadRequest);
            }

            if (!IdentityHelper.TryParseTenantAndUserName(identity, out var tenantID, out var username)
                || !TryParseCredential(credential, out var password))
            {
                throw new ApplicationException(InternalError.BadRequest);
            }

            var key = await configuration.GetSettingAsStringAsync(SETTING_PASSWORD_HASH_KEY);
            var hash = HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(password)).ToHex();
            Login login = await repository.Value.RetrieveAsync(Login.BuildPartitionKey(AuthenticationKind.Username, tenantID.ToKey()), Login.BuildRowKey(username));
            if (login == null || login.Credentials != hash)
            {
                throw new ApplicationException(InternalError.AuthenticationRequired);
            }

            return new()
            {
                User = login.User,
                Tenant = tenantID
            };
        }

        private static bool TryParseCredential(string? credential, out string password)
        {
            password = string.Empty;

            if (string.IsNullOrWhiteSpace(credential))
            {
                return false;
            }

            if (!credential.StartsWith(PASSWORD_LOGIN_CREDENTIAL_PREFIX))
            {
                return false;
            }

            password = credential[PASSWORD_LOGIN_CREDENTIAL_PREFIX.Length..];
            return !string.IsNullOrEmpty(password);
        }
    }
}
