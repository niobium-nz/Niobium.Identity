using System.Diagnostics.CodeAnalysis;

namespace Cod.Platform.Identity.API
{
#pragma warning disable CS8618
    [method: SetsRequiredMembers]
    internal class User() : ITrackable
    {
        [EntityKey(EntityKeyKind.PartitionKey)]
        public required string Prefix { get; set; }

        [EntityKey(EntityKeyKind.RowKey)]
        public required Guid ID { get; set; }

        [EntityKey(EntityKeyKind.Timestamp)]
        public DateTimeOffset? Timestamp { get; set; }

        [EntityKey(EntityKeyKind.ETag)]
        public string? ETag { get; set; }

        public DateTimeOffset? Created { get; set; }

        public bool Disabled { get; set; }

        public string? FirstIP { get; set; }

        public string? LastIP { get; set; }

        public static string BuildPartitionKey(Guid userID)
        {
            return userID.ToString()[..8];
        }

        public static string BuildRowKey(Guid userID)
        {
            return userID.ToString();
        }
    }
#pragma warning restore CS8618
}
