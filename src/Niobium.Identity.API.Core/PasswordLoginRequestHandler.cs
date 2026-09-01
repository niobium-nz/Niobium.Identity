using System.Security.Cryptography;
using System.Text;

namespace Niobium.Identity.API
{
    internal class PasswordLoginRequestHandler(Lazy<IRepository<Login>> repository, IConfigurationProvider configuration) : ILoginRequestHandler
    {
        public const string PASSWORD_LOGIN_CREDENTIAL_PREFIX = "PIN:";
        public const string SETTING_PASSWORD_HASH_KEY = "PASSWORD_HASH_KEY";

        public bool CanHandle(string scheme, string identity, string? credential)
            => String.Equals(scheme, AuthenticationScheme.BasicLoginScheme, StringComparison.OrdinalIgnoreCase)
                && TryParseCredential(credential, out _)
                && IdentityHelper.TryParseAppAndUserName(identity, out _, out _);

        public async Task<LoginResult> HandleAsync(string scheme, string identity, string? credential, string? clientIP)
        {
            if (!this.CanHandle(scheme, identity, credential))
            {
                throw new ApplicationException(Niobium.InternalError.BadRequest);
            }

            if (!IdentityHelper.TryParseAppAndUserName(identity, out Guid app, out string? username)
                || !TryParseCredential(credential, out string? password))
            {
                throw new ApplicationException(Niobium.InternalError.BadRequest);
            }

            string? key = await configuration.GetSettingAsStringAsync(SETTING_PASSWORD_HASH_KEY);
            string hash = HMACSHA256.HashData(Encoding.UTF8.GetBytes(key!), Encoding.UTF8.GetBytes(password)).ToHex();
            Login? login = await repository.Value.RetrieveAsync(Login.BuildPartitionKey(AuthenticationKind.Username, app.ToKey()), Login.BuildRowKey(username));
            return login == null || login.Credentials != hash
                ? throw new ApplicationException(Niobium.InternalError.AuthenticationRequired)
                : new()
                {
                    User = login.User,
                    App = app
                };
        }

        private static bool TryParseCredential(string? credential, out string password)
        {
            password = String.Empty;

            if (String.IsNullOrWhiteSpace(credential))
            {
                return false;
            }

            if (!credential.StartsWith(PASSWORD_LOGIN_CREDENTIAL_PREFIX, StringComparison.Ordinal))
            {
                return false;
            }

            password = credential[PASSWORD_LOGIN_CREDENTIAL_PREFIX.Length..];
            return !String.IsNullOrEmpty(password);
        }
    }
}
