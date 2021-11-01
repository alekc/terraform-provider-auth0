## 2.0.0
### Auth0_connection
* `enabled_client` is not computed anymore: you have to be explicit with the declaration
* `options` has been removed and split into individual configuration block. 
* `mfa` block has been split in `mfa_active` and `
* `realms` is no longer computed
* `import_mode` default value false
* `disable_signup` default value false
* `requires_username` default value false
* Added `enabledDatabaseCustomization` // TODO
* Salesforce, salesforce-community, salesforce-sandbox has been moved under the same block `salesforce`
