# VerifiedIDEAM

Sample code for MFA via Entra Verified ID and [External Authentication Method](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-external-method-manage) (EAM).

This sample supports two modes for signing JWT tokens:

| Mode | App Service Plan | Description |
|------|-----------------|-------------|
| **X.509 Certificate** (original) | B1 or higher | Downloads certificate from Key Vault and signs tokens locally |
| **Key Vault Remote Signing** | Free/Shared/any | Signs tokens remotely via Key Vault `CryptographyClient` — no certificate loaded in process |

See [Signing JWT tokens for Entra ID](#signing-jwt-tokens-for-entra-id) for details on each approach.

## How does EAM work?

![EAM sequence diagram](../media/VerifiedID-EAM-seq-diagram.png)

1.	The user starts authentication with Entra ID to use an app
2.	Entra ID determines that MFA is required and discovers that an EAM provider is configured
3.	API call to /.well-known/openid-configuration endpoint to get IDP details
4.	API call to /discovery/keys to retrieve the public key(s) for the EAM provider
5.	Entra ID generates the id_token_hint that contains claims about who the user is trying to sign in (preferred_username). 
6.	Entra ID makes a HTTP POST to the EAM providers /authorize endpoint (see details below).
    a. The EAM provider validates the form data in the call and the validity of the passed id_token_hint. If the EAM provider cannot process the call, it should return a HTTP 400 status code.
    b. If the The EAM provider can process the MFA request, it return an HTML response with the MFA UI.
7.	Entra ID sends the HTML to the browser
    a.	The EAM provider does its MFA magic, meaning it can be a multi-page sequence, calling backend APIs, etc. Control is with the EAM provider at this point.
8.	When the EAM provider is done with its MFA task, it needs to advance the UI in order to progress the Entra ID sign in flow. It therefore needs to redirect to a url in the EAM provider to handle this. 
    a. This endpoint checks the outcome of the MFA, and if successful, the EAM provider should generate an id_token to be given to Entra Id (see details below).
    b. The response is a small HTML page that contains the data (state and id_token) to be passed back to Entra’s redirect_uri
9.	Entra ID passes the small HTML page to the browser which immediately makes a form post back to Entra’s redirect_uri. Entra ID evaluates the supplied id_token with the MFA result and the sign in flow continues.

## How this sample looks like in action

This video shows using this sample in action

[![alt text](../media/EAM-screenshot.png)](https://github.com/cljung/did-samples/raw/refs/heads/main/media/VierifiedID-EAM-MFA.mp4)

## How does this sample work?

### OpenID Connect provider

This sample doesn't implement a full OIDC server. It just implements the three endpoints that EAM uses. This means it is a significantly reduced security risk.

| HTTP Method | API | Content-Type |
|------|--------|--------|
| GET | /v2.0/.well-known/openid-configuration | application/json |
| GET | /discovery/v2.0/keys | application/json |
| POST | /oauth2/v2.0/authorize	| application/x-www-form-urlencoded |

### Signing JWT tokens for Entra ID

The EAM provider needs to sign JWT id_tokens it emits as a result of the MFA. There are two approaches:

#### Option 1: X.509 Certificate (requires B1 plan or higher)

You can generate a self-signed certificate in Azure Key Vault and have the provider download the certificate (including private key) to sign tokens locally using `X509SigningCredentials`. The EAM provider app would need Certificate Permission "Get" and Secret Permission "Get" in Key Vault's Access policies.

This approach requires at least an Azure App Service **B1 plan** because the Free/Shared sandbox does not support loading X.509 certificates with private keys (`WEBSITE_LOAD_CERTIFICATES`).

![Certificate](../media/EAM-cert.png)

**appsettings.json** for this option requires a `CertificateIdentifier`:
```json
"AppSettings": {
    "KeyIdentifier": "https://<your-keyvault>.vault.azure.net/keys/<keyName>/<keyVersion>",
    "CertificateIdentifier": "https://<your-keyvault>.vault.azure.net/certificates/<certName>/<certVersion>"
}
```

#### Option 2: Key Vault Remote Signing (works on Free/Shared plans)

Instead of downloading a certificate with a private key, you can create a **self-signed certificate** in Key Vault and sign tokens remotely via the Key Vault `CryptographyClient.Sign()` API. The private key **never leaves Key Vault**, so no local X.509 private key loading is required.

> **Important**: Entra ID requires the JWKS endpoint to include the `x5c` parameter (X.509 certificate chain). The code fetches only the **public certificate** (`.Cer`) from Key Vault — not the private key — so this still works on Free/Shared plans.

This approach works on **any App Service plan, including Free (F1)**.

**Steps to set up:**

1. Create a self-signed certificate in Key Vault:
   ```bash
   az keyvault certificate create --vault-name <your-keyvault> --name VerifiedID-EAM-cert \
     --policy '{"issuerParameters":{"name":"Self"},"keyProperties":{"keyType":"RSA","keySize":2048},"x509CertificateProperties":{"subject":"CN=<your-app>.azurewebsites.net","validityInMonths":24}}'
   ```

2. Grant Key permissions (**Get, Sign, Verify**) and Certificate permission (**Get**) to your app registration:
   ```bash
   az keyvault set-policy --name <your-keyvault> --spn <your-app-client-id> \
     --key-permissions get sign verify --certificate-permissions get
   ```

3. Set both `KeyIdentifier` and `CertificateIdentifier` in **appsettings.json** (both point to the certificate's key):
   ```json
   "AppSettings": {
       "KeyIdentifier": "https://<your-keyvault>.vault.azure.net/keys/VerifiedID-EAM-cert/<version>",
       "CertificateIdentifier": "https://<your-keyvault>.vault.azure.net/certificates/VerifiedID-EAM-cert/<version>"
   }
   ```

4. (Optional) Store your client secret in Key Vault and use [Key Vault references](https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references) in App Service configuration to avoid plaintext secrets:
   ```bash
   az keyvault secret set --vault-name <your-keyvault> --name "AppSecret-<clientId>" --value "<secret>"
   az webapp identity assign --name <app-name> --resource-group <rg>
   az keyvault set-policy --name <your-keyvault> --object-id <managed-identity-id> --secret-permissions get
   az webapp config appsettings set --name <app-name> --resource-group <rg> \
     --settings "AzureAd__ClientSecret=@Microsoft.KeyVault(SecretUri=https://<your-keyvault>.vault.azure.net/secrets/AppSecret-<clientId>)"
   ```

### App Registration Requirements

The app registration used for EAM must have the following configured:

1. **Redirect URIs** (under Authentication > Web):
   - `https://login.microsoftonline.com/common/federation/externalauthprovider`
   - Your `authorization_endpoint` URL (e.g., `https://<your-app>.azurewebsites.net/<tenantId>/oauth2/v2.0/authorize`)
2. **ID tokens** enabled under Implicit grant
3. **API permissions**: `VerifiableCredential.Create.PresentRequest` (application) on the Verifiable Credentials Service Request API, with admin consent granted
4. **Supported account types**: Can be single-tenant or multi-tenant

> **Note**: If the `authorization_endpoint` is not registered as a reply URL, Entra will fail validation with `AADSTS5001255`.

### EAM configuration

When you configure EAM in the Entra portal (**Entra ID → Authentication methods → Add External MFA**), set the following:

![EAM configuration](../media/EAM-config.png)

| Item | Value | Description |
|------|--------|--------|
| Client ID | DID of your Verified ID authority | We need to pass the accepted issuing authority of the VC being requested. That could be configured in appsettings.json, etc, but that would limit the sample from being multi-tenant. This value is going to be passed as the `client_id` claim in the id_token_hint Entra ID passes in the /authorize call. |
| Discovery Endpoint | URL to .well-known/openid-configuration | The sample expects that the Entra tenant ID is part of the URL |
| App ID | guid	| The App ID of the registered application |

### Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `AADSTS5001255` | Failed to validate authorization URL | Ensure `authorization_endpoint` is registered as a reply URL on the app. Ensure JWKS includes `x5c`. Ensure the authorize endpoint returns HTTP 200 for bare GET requests. |
| `AADSTS501581` | EAM config does not exist or is not enabled | Delete and re-create the EAM entry. Ensure the target user/group is correct. |
| `AADSTS900491` | Service principal not found | Grant admin consent for the app in the tenant. |
| External MFA shows as "Non-usable" | Entra's background validation probe failed | Check that all three endpoints (discovery, JWKS, authorize) return HTTP 200. Check that JWKS includes `x5c`. |

The VerifiedEmployee credential the user presents needs to have been issued by a Verified ID authority that exists in the Entra tenant that holds the user. We can’t accept a VerifiedEmployee issued by anyone just because it matches the preferred_username, that would be a security threat. So, the presentation request needs to set the acceptedIssuers property of the request to target the Verified ID issuer for the correct Entra tenant. The problem here is that Entra’s EAM framework knows nothing about that we are planning to use Verified ID. However, there is a simple solution, and that is to use the client_id value in configuring the EAM provider. If we set this to the DID of the issuer, it gets passed to us in the /authority call and we can use it to target the correct issuer of the VerifiedEmployee credential. 

### Creating the presention request for VerifiedEmployee

When Entra ID calls our /authorize endpoint, we get the email in the `preferred_username` claim in the JWT id_token_hint Entra provides. 
The problem here is that it could be a B2B guest user invited from another tenant or a Microsoft Account. We are asking for a VerifiedEmployee from a member user in our directory, not a guest user. For this reason, the sample loads the .well-known/openid-configuration from the caller's Entra ID tenant so we can see if that information contains the user's domain. If it is a B2B guest user, we really should ask for a VerifiedEmployee from the user's home tenant, but the sample haven't implemented that. It asks for a VerifiedEmployee from _any_ issuer.

