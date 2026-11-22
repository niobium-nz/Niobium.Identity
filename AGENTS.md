# Working in Niobium.Identity

Read [model names and contract ownership](docs/model-contracts.md) before adding or
changing a Table model, key, fingerprint, serialized shape or file reference.
Use business property names with EntityKey attributes. Models privately own their
representation; domains own business rules and transitions, flows coordinate,
and framework adapters map/persist. Keep existing key/wire values compatible and
follow the documented separate rollout for legacy public contract renames.

Use feature branches and the owner-authorized delivery process. Inspect existing
workflow triggers before submission, verify available checks, native review and
a separate genuine approval, and monitor any resulting publication/deployment.
Do not push main, fabricate status, self-approve, or mutate production data.

## Azure resource naming

Use `rg-niobium-<service-slug>-<env>` for resource groups and
`<prefix>-<abbr>-<env>` for named service resources such as Functions and
vaults. Functions deployment packages use `<prefix>sts<env>` and application
data uses `<prefix>std<env>`. The `AzureWebJobsStorage` Blob and Table endpoints
in `infra/main.bicep` use the `std` account.
Identity uses the service slug `identity` and compact prefix `niobiumidentity`.
[Azure naming guide](https://github.com/niobium-nz/Niobium.DevOps/blob/f437f5a77dbec45296c0586b5bbe828d36eeb38b/docs/azure-resource-naming.md) · [Current DevOps documentation](https://github.com/niobium-nz/Niobium.DevOps/tree/main/docs)
