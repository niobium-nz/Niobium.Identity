using 'main.bicep'

param environmentName = readEnvironmentVariable('AZURE_ENV_NAME', 'dev')
param appShortName = readEnvironmentVariable('APP_SHORT_NAME', 'niobiumidentity')
param customDomainName = readEnvironmentVariable('CUSTOM_DOMAIN_NAME', '')
param isInteractiveDeployer = bool(readEnvironmentVariable('IS_INTERACTIVE_DEPLOYER', 'true'))
