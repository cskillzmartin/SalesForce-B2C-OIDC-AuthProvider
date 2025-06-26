# OpenID Connect Auth Provider Configuration

## Custom Metadata Type Setup

The OpenIDConnectAuthProvider requires a Custom Metadata Type record to be configured with the following specifications:

### Custom Metadata Type: `OpenIDConnectAuthProviderConfig__mdt`

#### Required Fields:
- `ClientId__c` (Text, 255) - The OpenID Connect client ID from your identity provider
- `ClientSecret__c` (Text, 255) - The OpenID Connect client secret (for confidential clients)
- `AuthorizationEndpoint__c` (Text, 255) - The authorization endpoint URL from your OpenID Connect provider
- `TokenEndpoint__c` (Text, 255) - The token endpoint URL from your OpenID Connect provider
- `UserInfoEndpoint__c` (Text, 255) - The UserInfo endpoint URL from your OpenID Connect provider
- `RedirectUri__c` (Text, 255) - The Salesforce callback URL

#### Optional Fields:
- `Scope__c` (Text, 255) - Custom scopes (defaults to "openid profile email")
- `Issuer__c` (Text, 255) - Expected issuer for JWT validation (optional but recommended)

#### Required Record:
- **Developer Name**: `Default`
- **Label**: `Default OpenID Connect Configuration`

### Example Configuration Values:

#### For Google OpenID Connect:
```
Developer Name: Default
Label: Default OpenID Connect Configuration
ClientId__c: 123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com
ClientSecret__c: [Your Google Client Secret]
AuthorizationEndpoint__c: https://accounts.google.com/o/oauth2/v2/auth
TokenEndpoint__c: https://oauth2.googleapis.com/token
UserInfoEndpoint__c: https://openidconnect.googleapis.com/v1/userinfo
RedirectUri__c: https://yourorg.my.salesforce.com/services/authcallback/OpenIDConnect
Scope__c: openid profile email
Issuer__c: https://accounts.google.com
```

#### For Azure AD OpenID Connect:
```
Developer Name: Default
Label: Default OpenID Connect Configuration
ClientId__c: 12345678-1234-1234-1234-123456789012
ClientSecret__c: [Your Azure AD Client Secret]
AuthorizationEndpoint__c: https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize
TokenEndpoint__c: https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token
UserInfoEndpoint__c: https://graph.microsoft.com/oidc/userinfo
RedirectUri__c: https://yourorg.my.salesforce.com/services/authcallback/OpenIDConnect
Scope__c: openid profile email
Issuer__c: https://login.microsoftonline.com/{tenant-id}/v2.0
```

#### For Auth0 OpenID Connect:
```
Developer Name: Default
Label: Default OpenID Connect Configuration
ClientId__c: your-auth0-client-id
ClientSecret__c: [Your Auth0 Client Secret]
AuthorizationEndpoint__c: https://your-domain.auth0.com/authorize
TokenEndpoint__c: https://your-domain.auth0.com/oauth/token
UserInfoEndpoint__c: https://your-domain.auth0.com/userinfo
RedirectUri__c: https://yourorg.my.salesforce.com/services/authcallback/OpenIDConnect
Scope__c: openid profile email
Issuer__c: https://your-domain.auth0.com/
```

### OpenID Connect Provider Setup:

1. **Register Application** with your OpenID Connect provider
2. **Configure Redirect URI** to match your Salesforce org:
   - Format: `https://[yourorg].my.salesforce.com/services/authcallback/[AuthProviderName]`
   - Example: `https://orgfarm-3aaceea11f-dev-ed.develop.my.site.com/services/authcallback/OpenIDConnect`
3. **Configure Response Types** to include `code` (authorization code flow)
4. **Set Scopes** to include at minimum: `openid profile email`
5. **Note the endpoints** from your provider's OpenID Connect discovery document (usually at `/.well-known/openid_configuration`)

### Deployment Steps:

1. Create the Custom Metadata Type with the required fields
2. Create a record with Developer Name = "Default"
3. Populate all required field values from your OpenID Connect provider
4. Deploy to your target org
5. Test the authentication flow

### Supported OpenID Connect Providers:

This auth provider has been designed to work with any compliant OpenID Connect provider, including:

- **Google** - Consumer and Workspace accounts
- **Microsoft Azure AD** - Azure Active Directory
- **Auth0** - Identity-as-a-Service platform
- **Okta** - Enterprise identity management
- **Amazon Cognito** - AWS identity service
- **Keycloak** - Open source identity and access management
- **Generic OpenID Connect** - Any RFC-compliant provider

### User Attribute Mapping:

The provider attempts to extract user information from the following sources in order:
1. **ID Token** (if present in token response)
2. **UserInfo Endpoint** (using access token)

#### Identifier Mapping (for User.FederationIdentifier):
- `sub` (OpenID Connect standard)
- `id` (some providers)
- `oid` (Microsoft/Azure)
- `user_id` (legacy providers)

#### Email Mapping:
- `email` (standard claim)
- `emails[0]` (array format)
- `preferred_username` (if contains @)

#### Name Mapping:
- `name` (full name)
- `given_name` + `family_name` (first + last)
- Individual `given_name` or `family_name`

### Troubleshooting:

- **Configuration Not Found**: Ensure Custom Metadata Type record exists with DeveloperName = "Default"
- **Invalid Endpoints**: Verify all endpoint URLs are correct and accessible
- **Token Exchange Failed**: Check client credentials and redirect URI configuration
- **UserInfo Request Failed**: Verify UserInfo endpoint and access token validity
- **Missing Claims**: Ensure your provider includes required claims in ID token or UserInfo response
- **JWT Validation Errors**: Check token expiration and issuer configuration

### Security Considerations:

- **Use HTTPS** for all endpoints and redirect URIs
- **Store client secrets securely** in Custom Metadata
- **Validate JWT signatures** in production environments
- **Set appropriate token expiration** times
- **Monitor authentication logs** for anomalies
- **Regularly rotate client secrets**
- **Use PKCE extension** when supported by provider
- **Implement proper logout flows** to clear sessions

### Advanced Configuration:

#### Custom Scopes:
You can request additional scopes by setting the `Scope__c` field. Always include `openid` as the first scope for OpenID Connect compliance.

#### JWT Validation:
Set the `Issuer__c` field to enable issuer validation for ID tokens. This adds an extra security layer by ensuring tokens come from the expected identity provider.

#### Token Refresh:
The provider supports automatic token refresh if your OpenID Connect provider returns refresh tokens. This enables longer-lived sessions without requiring re-authentication.

### Testing:

1. **Use the Test-Only Initialization URL** from the Auth Provider setup page
2. **Verify redirect** to your OpenID Connect provider
3. **Complete authentication** flow
4. **Check user creation** in Salesforce
5. **Validate user attributes** are populated correctly

### Integration with Experience Cloud Sites:

To use with Experience Cloud sites:
1. Configure the Auth Provider as described above
2. Add the provider to your site's login configuration
3. Customize the login page to include the OpenID Connect option
4. Test the flow from your community/site login page 