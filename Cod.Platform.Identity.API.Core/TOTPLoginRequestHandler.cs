using System.Text;

namespace Cod.Platform.Identity.API
{
    internal abstract class TOTPLoginRequestHandler(Lazy<IRepository<Login>> loginRepository, Lazy<IRepository<User>> userRepository)
        : LoginRequestHandler(loginRepository, userRepository), ILoginRequestHandler
    {
        public const string TOTPCredentialSplit = "|";
        public const string TOTPCredentialPrefix = "TOTP";
        public const int TOTPLength = 6;
        public static readonly TimeSpan TOTPValidity = TimeSpan.FromMinutes(10);

        public override bool CanHandle(string scheme, string identity, string? credential)
        {
            if (!base.CanHandle(scheme, identity, credential))
            {
                return false;
            }

            if (!string.Equals(scheme, AuthenticationScheme.BasicLoginScheme, StringComparison.InvariantCultureIgnoreCase))
            {
                return false;
            }

            if (!IdentityHelper.TryParseTenantAndUserName(identity, out _, out _))
            {
                return false;
            }

            if (!string.IsNullOrEmpty(credential))
            {
                if (!TryParseTOTP(credential, out _))
                {
                    return false;
                }
            }

            return true;
        }

        public override async Task<LoginResult> HandleAsync(string scheme, string identity, string? credential, string clientIP)
        {
            if (!CanHandle(scheme, identity, credential))
            {
                throw new ApplicationException(InternalError.BadRequest);
            }

            if (!IdentityHelper.TryParseTenantAndUserName(identity, out var tenantID, out var username))
            {
                throw new ApplicationException(InternalError.BadRequest);
            }

            var kind = DetermineAuthenticationKind(scheme, tenantID, username);
            if (kind == AuthenticationKind.Unknown)
            {
                throw new ApplicationException(InternalError.BadRequest);
            }

            LoginResult result = new();
            Login? login = await LoginRepository.RetrieveAsync(Login.BuildPartitionKey(kind, tenantID.ToKey()), Login.BuildRowKey(username));
            if (string.IsNullOrEmpty(credential))
            {
                var successSetup = await SetupTOTPAsync(kind, tenantID, username, login, clientIP);
                if (successSetup)
                {
                    result.Challenge = kind;
                }
                else
                {
                    result.Challenge = AuthenticationKind.Authenticator;
                }
                return result;
            }

            if (login == null)
            {
                throw new ApplicationException(InternalError.AuthenticationRequired);
            }

            if (!TryParseTOTP(login, out var totp1, out var createdAt)
                || !TryParseTOTP(credential, out var totp2)
                || totp1 != totp2
                || DateTimeOffset.UtcNow - createdAt > TOTPValidity)
            {
                throw new ApplicationException(InternalError.AuthenticationRequired);
            }

            result.User = login.User;
            result.Tenant = tenantID;
            return result;
        }

        protected virtual async Task<bool> SetupTOTPAsync(AuthenticationKind kind, Guid tenantID, string username, Login? login, string clientIP)
        {
            var totp = NewTOTP();
            var credential = $"{TOTPCredentialPrefix}{TOTPCredentialSplit}{totp}";
            var result = false;
            if (login == null)
            {
                await SetupNewLoginAsync(kind, tenantID, username, credential, clientIP);
                await ChallengeAsync(kind, tenantID, username, CredentialKind.TOTP, totp, clientIP);
                result = true;
            }
            else
            {
                if (login.Credentials == null || login.Credentials.StartsWith(TOTPCredentialPrefix))
                {
                    login.Credentials = credential;
                    await LoginRepository.UpdateAsync(login);
                    result = true;
                }
            }

            if (result)
            {
                await ChallengeAsync(kind, tenantID, username, CredentialKind.TOTP, totp, clientIP);
            }
            return result;
        }

        protected abstract AuthenticationKind DetermineAuthenticationKind(string scheme, Guid tenantID, string username);

        protected abstract Task ChallengeAsync(AuthenticationKind kind, Guid tenantID, string username, CredentialKind credentialKind, string credential, string clientIP);

        protected static bool TryParseTOTP(Login login, out string totp, out DateTimeOffset createdAt)
        {
            totp = string.Empty;
            createdAt = default;

            if (login.Credentials == null)
            {
                return false;
            }

            var parts = login.Credentials.Split(TOTPCredentialSplit);
            if (parts.Length != 2
                || parts[0] != TOTPCredentialPrefix
                || !TryParseTOTPFromTOTPCredential(parts[1], out totp, out createdAt)
                || !totp.All(char.IsDigit))
            {
                return false;
            }

            return true;
        }

        protected static bool TryParseTOTP(string credential, out string totp)
        {
            totp = string.Empty;
            var parts = credential.Split(TOTPCredentialSplit);
            if (parts.Length != 2
                || parts[0] != TOTPCredentialPrefix
                || parts[1].Length != TOTPLength
                || !parts[1].All(char.IsDigit))
            {
                return false;
            }

            totp = parts[1];
            return true;
        }

        protected static string NewTOTP()
        {
            var now = DateTimeOffset.UtcNow;
            var random = new Random(now.Microsecond);
            var digits = new StringBuilder(TOTPLength);
            for (int i = 0; i < TOTPLength; i++)
            {
                digits.Append(random.Next(9));
            }

            return $"{digits}@{now:o}";
        }

        private static bool TryParseTOTPFromTOTPCredential(string totpCredential, out string totp, out DateTimeOffset createdAt)
        {
            totp = string.Empty;
            createdAt = default;
            var parts = totpCredential.Split('@');
            if (parts.Length != 2 || !DateTimeOffset.TryParse(parts[1], out createdAt))
            {
                return false;
            }

            totp = parts[0];
            return totp.Length == TOTPLength && totp.All(char.IsDigit);
        }
    }
}
