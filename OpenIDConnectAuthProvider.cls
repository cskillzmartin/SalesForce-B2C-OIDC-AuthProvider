public with sharing class OpenIDConnectAuthProvider extends Auth.AuthProviderPluginClass {

    /* --------------------------------------------------------------------- */
    /*  Required override - tie plug-in to its configuration metadata       */
    /* --------------------------------------------------------------------- */
    public String getCustomMetadataType() {
        return 'OpenIDConnectAuthProviderConfig__mdt';
    }

    /* --------------------------------------------------------------------- */
    /*  Cached configuration helper                                          */
    /* --------------------------------------------------------------------- */
    private OpenIDConnectAuthProviderConfig__mdt cfg {
        get {
            if (cfg == null) {
                // One-record convention keeps the plug-in stateless.
                List<OpenIDConnectAuthProviderConfig__mdt> configs = [SELECT clientId__c, clientSecret__c, 
                               authorizationEndpoint__c, tokenEndpoint__c, userInfoEndpoint__c,
                               redirectUri__c, scope__c, issuer__c
                          FROM OpenIDConnectAuthProviderConfig__mdt
                          WHERE DeveloperName = 'Default'
                          LIMIT 1];
                          
                if (configs.isEmpty()) {
                    throw new Auth.AuthProviderPluginException(
                        'OpenID Connect Auth Provider configuration not found. Please create a OpenIDConnectAuthProviderConfig__mdt record with DeveloperName = "Default"'
                    );
                }
                
                cfg = configs[0];
                
                // Validate required fields
                if (String.isBlank(cfg.ClientId__c)) {
                    throw new Auth.AuthProviderPluginException('OpenID Connect Auth Provider: ClientId is required');
                }
                if (String.isBlank(cfg.AuthorizationEndpoint__c)) {
                    throw new Auth.AuthProviderPluginException('OpenID Connect Auth Provider: AuthorizationEndpoint is required');
                }
                if (String.isBlank(cfg.TokenEndpoint__c)) {
                    throw new Auth.AuthProviderPluginException('OpenID Connect Auth Provider: TokenEndpoint is required');
                }
                if (String.isBlank(cfg.RedirectUri__c)) {
                    throw new Auth.AuthProviderPluginException('OpenID Connect Auth Provider: RedirectUri is required');
                }
            }
            return cfg;
        }
        private set;
    }

    /* --------------------------------------------------------------------- */
    /*  Step 1 - Build the OpenID Connect authorize URL                     */
    /* --------------------------------------------------------------------- */
    public PageReference initiate(Map<String,String> pluginConfig,
                                           String state) {
        try {
            String scope = String.isNotBlank(cfg.Scope__c) ? cfg.Scope__c : 'openid profile email';
            
            String url = cfg.AuthorizationEndpoint__c + 
                        '?client_id='      + EncodingUtil.urlEncode(cfg.ClientId__c, 'UTF-8') +
                        '&response_type=code' +
                        '&redirect_uri='   + EncodingUtil.urlEncode(cfg.RedirectUri__c, 'UTF-8') +
                        '&scope='          + EncodingUtil.urlEncode(scope, 'UTF-8') +
                        '&state='          + EncodingUtil.urlEncode(state, 'UTF-8') +
                        '&nonce='          + String.valueOf(Crypto.getRandomLong());
            
            System.debug('OpenID Connect Auth URL: ' + url);
            return new PageReference(url);
        } catch (Exception e) {
            throw new Auth.AuthProviderPluginException('Failed to initiate OpenID Connect authentication: ' + e.getMessage());
        }
    }

    /* --------------------------------------------------------------------- */
    /*  Step 2 - Handle authorization code callback and exchange for tokens  */
    /* --------------------------------------------------------------------- */
    public Auth.AuthProviderTokenResponse handleCallback(
            Map<String,String> pluginConfig,
            Auth.AuthProviderCallbackState callbackState) {

        try {
            String authCode = callbackState.queryParameters.get('code');
            if (String.isBlank(authCode)) {
                String error = callbackState.queryParameters.get('error');
                String errorDescription = callbackState.queryParameters.get('error_description');
                String errorMessage = 'OpenID Connect provider did not return authorization code';
                if (String.isNotBlank(error)) {
                    errorMessage += '. Error: ' + error;
                    if (String.isNotBlank(errorDescription)) {
                        errorMessage += '. Description: ' + errorDescription;
                    }
                }
                throw new Auth.AuthProviderPluginException(errorMessage);
            }

            // Exchange authorization code for tokens
            Map<String, Object> tokenResponse = exchangeCodeForTokens(authCode);
            
            String accessToken = (String)tokenResponse.get('access_token');
            String refreshToken = (String)tokenResponse.get('refresh_token');
            String idToken = (String)tokenResponse.get('id_token');
            
            if (String.isBlank(accessToken)) {
                throw new Auth.AuthProviderPluginException('OpenID Connect token exchange did not return access_token');
            }

            // Validate ID token if present
            if (String.isNotBlank(idToken)) {
                validateJwtStructure(idToken);
            }

            // Build token response for downstream methods.
            Auth.AuthProviderTokenResponse resp = new Auth.AuthProviderTokenResponse(
                'OpenIDConnect',           // provider name
                accessToken,               // access token
                refreshToken,              // refresh token
                callbackState.queryParameters.get('state') // state
            );
            resp.idToken = idToken;
            return resp;
        } catch (Exception e) {
            throw new Auth.AuthProviderPluginException('Failed to handle OpenID Connect callback: ' + e.getMessage());
        }
    }

    /* --------------------------------------------------------------------- */
    /*  Step 3 - Get user info from ID token only                           */
    /* --------------------------------------------------------------------- */
    public Auth.UserData getUserInfo(Map<String,String> pluginConfig,
                                              Auth.AuthProviderTokenResponse resp) {
        try {
            // ID token is required for user info extraction
            if (String.isBlank(resp.idToken)) {
                throw new Auth.AuthProviderPluginException('OpenID Connect response missing required ID token');
            }
            
            // Decode JWT to extract user claims
            Map<String,Object> userInfo = decodeJwt(resp.idToken);

            // Extract user attributes
            String identifier = extractIdentifier(userInfo);
            String email = extractEmail(userInfo);
            String firstName = (String)userInfo.get('given_name');
            String lastName = (String)userInfo.get('family_name');
            String fullName = buildFullName(firstName, lastName, (String)userInfo.get('name'));
            String username = String.isNotBlank(email) ? email : identifier;
            
            // Validate required fields
            if (String.isBlank(identifier)) {
                throw new Auth.AuthProviderPluginException('OpenID Connect ID token missing required identifier claim');
            }
            
            Auth.UserData u = new Auth.UserData(
                identifier,                  // identifier - maps to User.FederationIdentifier
                firstName,                   // firstName
                lastName,                    // lastName  
                fullName,                    // fullName
                email,                       // email
                null,                        // link - not used
                username,                    // username
                null,                        // locale - could be extracted from claims if needed
                'OpenIDConnect',             // provider
                null,                        // siteLoginUrl - not used
                new Map<String,String>()     // attributeMap - must be Map<String,String>
            );
            
            return u;
        } catch (Exception e) {
            throw new Auth.AuthProviderPluginException('Failed to extract user info from OpenID Connect ID token: ' + e.getMessage());
        }
    }

    /* --------------------------------------------------------------------- */
    /*  Token refresh implementation                                         */
    /* --------------------------------------------------------------------- */
    public override Auth.OAuthRefreshResult refresh(Map<String,String> pluginConfig,
                                                    String refreshToken) {
        if (String.isBlank(refreshToken)) {
            return null; // No refresh token available
        }
        
        try {
            Map<String, Object> tokenResponse = refreshAccessToken(refreshToken);
            
            String newAccessToken = (String)tokenResponse.get('access_token');
            String newRefreshToken = (String)tokenResponse.get('refresh_token');
            
            if (String.isBlank(newAccessToken)) {
                return null; // Refresh failed
            }
            
            // Use existing refresh token if new one not provided
            if (String.isBlank(newRefreshToken)) {
                newRefreshToken = refreshToken;
            }
            
            return new Auth.OAuthRefreshResult(newAccessToken, newRefreshToken);
        } catch (Exception e) {
            System.debug('OpenID Connect token refresh failed: ' + e.getMessage());
            return null; // Return null to trigger re-authentication
        }
    }

    /* --------------------------------------------------------------------- */
    /*  Utility - Exchange authorization code for tokens                    */
    /* --------------------------------------------------------------------- */
    private Map<String, Object> exchangeCodeForTokens(String authCode) {
        HttpRequest req = new HttpRequest();
        req.setEndpoint(cfg.TokenEndpoint__c);
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
        req.setHeader('Accept', 'application/json');
        
        String body = 'grant_type=authorization_code' +
                     '&code=' + EncodingUtil.urlEncode(authCode, 'UTF-8') +
                     '&redirect_uri=' + EncodingUtil.urlEncode(cfg.RedirectUri__c, 'UTF-8') +
                     '&client_id=' + EncodingUtil.urlEncode(cfg.ClientId__c, 'UTF-8');
        
        if (String.isNotBlank(cfg.ClientSecret__c)) {
            body += '&client_secret=' + EncodingUtil.urlEncode(cfg.ClientSecret__c, 'UTF-8');
        }
        
        req.setBody(body);
        
        Http http = new Http();
        HttpResponse res = http.send(req);
        
        if (res.getStatusCode() != 200) {
            throw new Auth.AuthProviderPluginException('Token exchange failed with status: ' + res.getStatusCode() + ' - ' + res.getBody());
        }
        
        return (Map<String, Object>)JSON.deserializeUntyped(res.getBody());
    }

    /* --------------------------------------------------------------------- */
    /*  Utility – Refresh access token using refresh token                  */
    /* --------------------------------------------------------------------- */
    private Map<String, Object> refreshAccessToken(String refreshToken) {
        HttpRequest req = new HttpRequest();
        req.setEndpoint(cfg.TokenEndpoint__c);
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
        req.setHeader('Accept', 'application/json');
        
        String body = 'grant_type=refresh_token' +
                     '&refresh_token=' + EncodingUtil.urlEncode(refreshToken, 'UTF-8') +
                     '&client_id=' + EncodingUtil.urlEncode(cfg.ClientId__c, 'UTF-8');
        
        if (String.isNotBlank(cfg.ClientSecret__c)) {
            body += '&client_secret=' + EncodingUtil.urlEncode(cfg.ClientSecret__c, 'UTF-8');
        }
        
        req.setBody(body);
        
        Http http = new Http();
        HttpResponse res = http.send(req);
        
        if (res.getStatusCode() != 200) {
            throw new Auth.AuthProviderPluginException('Token refresh failed with status: ' + res.getStatusCode() + ' - ' + res.getBody());
        }
        
        return (Map<String, Object>)JSON.deserializeUntyped(res.getBody());
    }



    /* --------------------------------------------------------------------- */
    /*  Utility - Validate JWT structure and basic security properties       */
    /* --------------------------------------------------------------------- */
    private static void validateJwtStructure(String jwt) {
        if (String.isBlank(jwt)) {
            throw new Auth.AuthProviderPluginException('JWT token is blank');
        }
        
        List<String> parts = jwt.split('\\.');
        if (parts.size() != 3) {
            throw new Auth.AuthProviderPluginException('Invalid JWT structure - expected 3 parts');
        }
        
        // Validate token hasn't expired
        Map<String,Object> claims = decodeJwt(jwt);
        if (claims.containsKey('exp')) {
            Long exp = extractLongClaim(claims, 'exp');
            Long nowSec = DateTime.now().getTime() / 1000;
            if (exp < nowSec) {
                throw new Auth.AuthProviderPluginException('JWT token has expired');
            }
        }
        
        // Validate issuer if configured
        if (String.isNotBlank(cfg.Issuer__c) && claims.containsKey('iss')) {
            String issuer = (String)claims.get('iss');
            if (!cfg.Issuer__c.equals(issuer)) {
                throw new Auth.AuthProviderPluginException('JWT issuer mismatch. Expected: ' + cfg.Issuer__c + ', Got: ' + issuer);
            }
        }
    }

    /* --------------------------------------------------------------------- */
    /*  Utility - Decode base64url JWT payload into a Map.                    */
    /* --------------------------------------------------------------------- */
    private static Map<String,Object> decodeJwt(String jwt) {
        List<String> parts = jwt.split('\\.');
        if (parts.size() < 2) {
            throw new Auth.AuthProviderPluginException('Invalid JWT');
        }
        String payload = parts[1];
        payload = payload.replace('-', '+').replace('_', '/');
        while ( (payload.length() - (4 * (payload.length() / 4))) != 0 ) {
            payload += '=';
        }
        try {
            Blob jsonBlob = EncodingUtil.base64Decode(payload);
            return (Map<String,Object>)JSON.deserializeUntyped(jsonBlob.toString());
        } catch (Exception e) {
            throw new Auth.AuthProviderPluginException('Failed to decode JWT payload: ' + e.getMessage());
        }
    }

    /* --------------------------------------------------------------------- */
    /*  Utility - Extract identifier from various possible claim formats    */
    /* --------------------------------------------------------------------- */
    private static String extractIdentifier(Map<String,Object> userInfo) {
        // Try different identifier claim formats used by OpenID Connect providers
        if (userInfo.containsKey('sub')) {
            return (String)userInfo.get('sub');
        }
        
        if (userInfo.containsKey('id')) {
            return (String)userInfo.get('id');
        }
        
        if (userInfo.containsKey('oid')) {
            return (String)userInfo.get('oid');
        }
        
        if (userInfo.containsKey('user_id')) {
            return (String)userInfo.get('user_id');
        }
        
        return null;
    }

    /* --------------------------------------------------------------------- */
    /*  Utility - Extract email from various possible claim formats          */
    /* --------------------------------------------------------------------- */
    private static String extractEmail(Map<String,Object> userInfo) {
        // Try different email claim formats used by OpenID Connect providers
        if (userInfo.containsKey('email')) {
            return (String)userInfo.get('email');
        }
        
        if (userInfo.containsKey('emails')) {
            List<Object> emails = (List<Object>)userInfo.get('emails');
            if (emails != null && !emails.isEmpty()) {
                return (String)emails[0];
            }
        }
        
        if (userInfo.containsKey('preferred_username')) {
            String username = (String)userInfo.get('preferred_username');
            if (String.isNotBlank(username) && username.contains('@')) {
                return username;
            }
        }
        
        return null;
    }

    /* --------------------------------------------------------------------- */
    /*  Utility - Build full name safely                                     */
    /* --------------------------------------------------------------------- */
    private static String buildFullName(String firstName, String lastName, String fullName) {
        // Use provided full name if available
        if (String.isNotBlank(fullName)) {
            return fullName;
        }
        
        // Build from first and last name
        if (String.isNotBlank(firstName) && String.isNotBlank(lastName)) {
            return firstName + ' ' + lastName;
        } else if (String.isNotBlank(firstName)) {
            return firstName;
        } else if (String.isNotBlank(lastName)) {
            return lastName;
        }
        return '';
    }

    /* --------------------------------------------------------------------- */
    /*  Utility - Extract Long claim safely                                  */
    /* --------------------------------------------------------------------- */
    private static Long extractLongClaim(Map<String,Object> claims, String claimName) {
        Object claimValue = claims.get(claimName);
        if (claimValue instanceof Decimal) {
            return ((Decimal)claimValue).longValue();
        } else if (claimValue instanceof Long) {
            return (Long)claimValue;
        } else if (claimValue instanceof Integer) {
            return ((Integer)claimValue).longValue();
        }
        return 0L;
    }
}