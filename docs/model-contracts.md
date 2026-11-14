# Business names and model contract ownership

The owner's rule of 14 November 2026 applies to Identity as well as other Niobium
projects. Read the [framework explanation and examples](https://github.com/niobium-nz/Niobium/blob/main/docs/model-contracts.md).

Use names that describe the value represented by a Table model property, then
annotate its storage role with `EntityKeyKind.PartitionKey` or `RowKey`.
The shared repository writes the required physical column names. Do not call a
composite authentication scope merely a tenant, and do not introduce Azure SDK
mapping into authentication business code.

Models own identity encoding, normalized lookup values, serialized formats and
file-path conventions. Keep implementation helpers private behind meaningful
factory/lookup/comparison operations. Domains own authentication policy, allowed
transitions and persistence; flows coordinate them. A private encoding helper
must not become a hidden authorization or credential-access decision.

The mapper enumerates public instance properties, including computed values.
JSON attributes are not Table exclusions. Avoid duplicate key aliases, preserve
materialization requirements, and verify old rows through the actual adapter.

## Legacy Login boundary

At main `0a3f8aa`, the internal
[Login](../src/Niobium.Identity.API.Core/Login.cs) model still has generic names.
Its partition encodes authentication kind and optional application; its row
contains the trimmed login identity. Its helper methods and callers depend on
those representations. The owner selected a separate compatibility rollout for
legacy contract renames, so these are inventoried rather than changed here.

That rollout must preserve lookup ranges, authentication behavior, normalization,
serialized values and consumed framework Profile/OpenID APIs. A naming change is
not authority to migrate credentials or alter production identity records.

## Documentation delivery boundary

The production job previously accepted any pull-request event. Its guard now
requires the main ref, preserving main push/manual behavior and preventing a PR
from deploying unreviewed source. This is a delivery safeguard for this change;
no identity model or runtime policy is renamed. The existing test job still runs
on matching feature pushes and PRs.
