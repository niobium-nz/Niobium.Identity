targetScope = 'resourceGroup'

@description('The location of the resource group.')
param location string = resourceGroup().location

@minLength(3)
@maxLength(4)
@description('Name of the environment.')
param environmentName string

@description('Short name used as a prefix for Azure resources. Keep it globally unique where required.')
param appShortName string

@description('App settings to project into the container app environment.')
param appSettings array = []

@description('Automatically set by azd. True if the app already exists.')
param appExists bool = false

@description('Custom domain name bind to the container app.')
param customDomainName string = ''

@description('Id of the user identity to be used for testing and debugging. This is not required in production. Leave empty if not needed. Can optionally use deployer().objectId if manually deployed')
param userIdentityPrincipalId string = ''

@description('Indicates whether the deployment is interactive.')
param isInteractiveDeployer bool = true

var abbrs = loadJsonContent('./abbreviations.json')

var dataStorageAccountName = replace('${appShortName}-${abbrs.storageStorageAccounts}d${environmentName}', '-', '')
module dataStorageAccount 'br/public:avm/res/storage/storage-account:0.32.0' = {
  params: {
    name: dataStorageAccountName
    skuName: 'Standard_LRS'
    kind: 'StorageV2'
    publicNetworkAccess: 'Enabled'
    location: location
    networkAcls: {
      defaultAction: 'Allow'
    }
    allowBlobPublicAccess: true
    blobServices: {
      corsRules: [
        {
          allowedOrigins: ['*']
          allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'MERGE', 'OPTIONS']
          maxAgeInSeconds: 0
          exposedHeaders: ['*']
          allowedHeaders: ['*']
        }
      ]
    }
    tableServices: {
      corsRules: [
        {
          allowedOrigins: ['*']
          allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'MERGE', 'OPTIONS']
          maxAgeInSeconds: 0
          exposedHeaders: ['*']
          allowedHeaders: ['*']
        }
      ]
    }
  }
}
var storageSettings = [ 
    { 
        name: 'AzureWebJobsStorage__blobServiceUri'
        value: dataStorageAccount.outputs.serviceEndpoints.blob
    }
    { 
        name: 'AzureWebJobsStorage__tableServiceUri'
        value: dataStorageAccount.outputs.serviceEndpoints.table
    }
]

module app 'function-app.bicep' = {
  params: {
    location: location
    appShortName: appShortName
    environmentName: environmentName
    appSettings: concat(appSettings, storageSettings)
    customDomainName: customDomainName
    userIdentityPrincipalId: userIdentityPrincipalId
    isInteractiveDeployer: isInteractiveDeployer
  }
}

module rbac 'rbac.bicep' = {
  params: {
    userIdentityPrincipalId: userIdentityPrincipalId
    managedIdentityPrincipalId: app.outputs.managedIdentityPrincipalId
    storageAccountNames: [dataStorageAccountName]
  }
}

output functionAppName string = app.outputs.functionAppName
output dataStorageAccountName string = dataStorageAccount.outputs.name
output appInsightsName string = app.outputs.appInsightsName
output keyVaultName string = app.outputs.keyVaultName