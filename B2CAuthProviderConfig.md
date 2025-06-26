# B2C Auth Provider Configuration

## Custom Metadata Type Setup

The B2CAuthProvider requires a Custom Metadata Type record to be configured with the following specifications:

### Custom Metadata Type: `B2CAuthProviderConfig__mdt`

#### Required Fields:
- `ClientId__c` (Text, 255) - The Azure B2C Application (client) ID
- `ClientSecret__c` (Text, 255) - The Azure B2C client secret (if using confidential client)
- `Tenant__c` (Text, 255) - The Azure B2C tenant name (without .onmicrosoft.com)
- `Policy__c` (Text, 255) - The Azure B2C user flow/policy name (e.g., B2C_1_SignUpSignIn)
- `RedirectUri__c` (Text, 255) - The Salesforce callback URL

#### Required Record:
- **Developer Name**: `Default`
- **Label**: `Default B2C Configuration`

### Example Configuration Values:

```
Developer Name: Default
Label: Default B2C Configuration
ClientId__c: 12345678-1234-1234-1234-123456789012
ClientSecret__c: [Your B2C Client Secret]
Tenant__c: yourtenantname
Policy__c: B2C_1_SignUpSignIn
RedirectUri__c: https://yourorg.my.salesforce.com/services/authcallback/B2C
```

### Azure B2C App Registration Setup:

1. **Create App Registration** in Azure B2C
2. **Set Redirect URI** to match your Salesforce org:
   - Format: `https://[yourorg].my.salesforce.com/services/authcallback/[AuthProviderName]`
   - Example: `https://orgfarm-3aaceea11f-dev-ed.develop.my.site.com/services/authcallback/B2C`
3. **Configure ID Token** to be returned
4. **Set up User Flow** (Sign-up and Sign-in policy)
5. **Configure Claims** to include:
   - `oid` (Object ID) - Required for user identification
   - `given_name` - First name
   - `family_name` - Last name
   - `emails` or `email` - Email address

### Deployment Steps:

1. Create the Custom Metadata Type with the required fields
2. Create a record with Developer Name = "Default"
3. Populate all required field values
4. Deploy to your target org
5. Test the authentication flow

### Troubleshooting:

- **Remote_Error**: Usually indicates missing or misconfigured metadata
- **Invalid JWT**: Check that B2C is configured to return ID tokens
- **Missing Claims**: Ensure B2C user flow includes required claims
- **Redirect URI Mismatch**: Verify the redirect URI matches exactly between B2C and Salesforce

### Security Considerations:

- Store client secrets securely
- Use HTTPS for all redirect URIs
- Regularly rotate client secrets
- Monitor authentication logs for anomalies
- Validate JWT signatures in production (currently commented out in code) 