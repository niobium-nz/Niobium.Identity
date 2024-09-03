namespace Cod.Platform.Identity.API
{
    internal class IdentityHelper
    {
        public static bool TryParseTenantAndUserName(string identity, out Guid tenantID, out string username)
        {
            tenantID = Guid.Empty;
            username = string.Empty;

            if (string.IsNullOrWhiteSpace(identity))
            {
                return false;
            }

            var parts = identity.Split('|');
            if (parts.Length != 2)
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(parts[0]) || string.IsNullOrWhiteSpace(parts[1]))
            {
                return false;
            }

            if (!Guid.TryParse(parts[0], out tenantID))
            {
                return false;
            }

            username = parts[1];
            return true;
        }
    }
}
