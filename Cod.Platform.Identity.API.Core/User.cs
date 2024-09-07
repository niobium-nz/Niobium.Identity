namespace Cod.Platform.Identity.API
{
    internal class User : ITrackable
    {
        [EntityKey(EntityKeyKind.PartitionKey)]
        public string PartitionKey { get; set; }

        [EntityKey(EntityKeyKind.RowKey)]
        public string RowKey { get; set; }

        [EntityKey(EntityKeyKind.Timestamp)]
        public DateTimeOffset? Timestamp { get; set; }

        [EntityKey(EntityKeyKind.ETag)]
        public string? ETag { get; set; }

        public DateTimeOffset? Created { get; set; }

        public bool Disabled { get; set; }

        public string? FirstIP { get; set; }

        public string? LastIP { get; set; }

        public static string BuildPartitionKey(Guid value)
        {
            return value.ToString()[..8];
        }

        public static string BuildRowKey(Guid value)
        {
            return value.ToString();
        }

        public Guid GetID()
        {
            return Guid.Parse(RowKey);
        }

        public void SetID(Guid value)
        {
            RowKey = BuildRowKey(value);
        }
    }
}
