using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Niobium.Identity.API
{
#pragma warning disable CS8618
    [method: SetsRequiredMembers]
    internal class Login() : ITrackable
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

        public static string BuildPartitionKey(AuthenticationKind kind) => BuildPartitionKey((int)kind);

        public static string BuildPartitionKey(int kind) => BuildPartitionKey(kind, default);

        public static string BuildPartitionKey(AuthenticationKind kind, string app) => BuildPartitionKey((int)kind, app);

        public static string BuildPartitionKey(int kind, string? app)
        {
            app ??= String.Empty;
            return $"{kind}|{app.Trim()}";
        }

        public static string BuildRowKey(string identity) => identity is null ? throw new ArgumentNullException(nameof(identity)) : identity.Trim();

        public string GetIdentity() => this.RowKey.Trim();

        public AuthenticationKind GetKind() => (AuthenticationKind)Int32.Parse(this.PartitionKey.Split('|')[0], CultureInfo.InvariantCulture);

        public bool IsKindOf(AuthenticationKind type) => this.IsKindOf((int)type);

        public bool IsKindOf(int type) => this.GetKind() == (AuthenticationKind)type;
    }
#pragma warning restore CS8618
}
