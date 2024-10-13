using Cod.Identity;
using System.Diagnostics.CodeAnalysis;

namespace Cod.Platform.Identity.API
{
    [method: SetsRequiredMembers]
#pragma warning disable CS8618
    internal class Login() : ITrackable
#pragma warning restore CS8618
    {
        [EntityKey(EntityKeyKind.PartitionKey)]
        public required string PartitionKey { get; set; }

        [EntityKey(EntityKeyKind.RowKey)]
        public required string RowKey { get; set; }

        [EntityKey(EntityKeyKind.Timestamp)]
        public DateTimeOffset? Timestamp { get; set; }

        [EntityKey(EntityKeyKind.ETag)]
        public string? ETag { get; set; }

        public DateTimeOffset? Created { get; set; }

        public string? Credentials { get; set; }

        public Guid User { get; set; }

        public static string BuildPartitionKey(AuthenticationKind kind)
        {
            return BuildPartitionKey((int)kind);
        }

        public static string BuildPartitionKey(int kind)
        {
            return BuildPartitionKey(kind, default);
        }

        public static string BuildPartitionKey(AuthenticationKind kind, string app)
        {
            return BuildPartitionKey((int)kind, app);
        }

        public static string BuildPartitionKey(int kind, string? app)
        {
            app ??= string.Empty;
            return $"{kind}|{app.Trim()}";
        }

        public static string BuildRowKey(string identity)
        {
            return identity is null ? throw new ArgumentNullException(nameof(identity)) : identity.Trim();
        }

        public string GetIdentity()
        {
            return RowKey.Trim();
        }

        public AuthenticationKind GetKind()
        {
            return (AuthenticationKind)int.Parse(PartitionKey.Split('|')[0]);
        }

        public bool IsKindOf(AuthenticationKind type)
        {
            return IsKindOf((int)type);
        }

        public bool IsKindOf(int type)
        {
            return GetKind() == (AuthenticationKind)type;
        }
    }
}
