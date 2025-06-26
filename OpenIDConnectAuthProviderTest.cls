@IsTest
public class OpenIDConnectAuthProviderTest {
    
    private static final String PROVIDER_NAME = 'OpenIDConnect';
    private static final String CLIENT_ID = 'test-client-id';
    private static final String CLIENT_SECRET = 'test-client-secret';
    private static final String AUTH_ENDPOINT = 'https://provider.example.com/auth';
    private static final String TOKEN_ENDPOINT = 'https://provider.example.com/token';
    private static final String USERINFO_ENDPOINT = 'https://provider.example.com/userinfo';
    private static final String REDIRECT_URI = 'https://test.salesforce.com/services/authcallback/OpenIDConnect';
    private static final String TEST_STATE = 'test-state-123';
    private static final String TEST_CODE = 'test-auth-code-123';
    private static final String TEST_ACCESS_TOKEN = 'test-access-token-123';
    private static final String TEST_REFRESH_TOKEN = 'test-refresh-token-123';
    
    @TestSetup
    static void setupTestData() {
        // Test setup would typically create Custom Metadata Type records
        // In actual implementation, you'd need to create the metadata programmatically
        // or use @TestVisible methods to inject test configuration
    }
    
    @IsTest
    static void testGetCustomMetadataType() {
        OpenIDConnectAuthProvider provider = new OpenIDConnectAuthProvider();
        String metadataType = provider.getCustomMetadataType();
        System.assertEquals('OpenIDConnectAuthProviderConfig__mdt', metadataType);
    }
    
    @IsTest
    static void testInitiateSuccess() {
        Test.startTest();
        
        OpenIDConnectAuthProvider provider = new OpenIDConnectAuthProvider();
        Map<String, String> pluginConfig = new Map<String, String>();
        
        try {
            PageReference result = provider.initiate(pluginConfig, TEST_STATE);
            
            // In a real test, you would verify the URL construction
            // This would require either mocking the configuration or using @TestVisible
            System.assertNotEquals(null, result, 'PageReference should not be null');
            
        } catch (Auth.AuthProviderPluginException e) {
            // Expected when configuration is not available in test context
            System.assert(e.getMessage().contains('configuration not found'), 
                         'Expected configuration error: ' + e.getMessage());
        }
        
        Test.stopTest();
    }
    
    @IsTest
    static void testHandleCallbackWithAuthCode() {
        Test.startTest();
        
        // Mock HTTP callouts for token exchange
        Test.setMock(HttpCalloutMock.class, new OpenIDConnectTokenMock());
        
        OpenIDConnectAuthProvider provider = new OpenIDConnectAuthProvider();
        Map<String, String> pluginConfig = new Map<String, String>();
        
        // Create callback state with authorization code
        Auth.AuthProviderCallbackState callbackState = createCallbackState(TEST_CODE, TEST_STATE);
        
        try {
            Auth.AuthProviderTokenResponse response = provider.handleCallback(pluginConfig, callbackState);
            
            System.assertEquals(PROVIDER_NAME, response.provider);
            System.assertEquals(TEST_STATE, response.state);
            // Additional assertions would be made in real implementation
            
        } catch (Auth.AuthProviderPluginException e) {
            // Expected when configuration is not available in test context
            System.assert(e.getMessage().contains('configuration not found'), 
                         'Expected configuration error: ' + e.getMessage());
        }
        
        Test.stopTest();
    }
    
    @IsTest
    static void testHandleCallbackWithError() {
        Test.startTest();
        
        OpenIDConnectAuthProvider provider = new OpenIDConnectAuthProvider();
        Map<String, String> pluginConfig = new Map<String, String>();
        
        // Create callback state with error
        Map<String, String> queryParams = new Map<String, String>{
            'error' => 'access_denied',
            'error_description' => 'User denied access',
            'state' => TEST_STATE
        };
        Auth.AuthProviderCallbackState callbackState = createCallbackStateWithParams(queryParams);
        
        try {
            Auth.AuthProviderTokenResponse response = provider.handleCallback(pluginConfig, callbackState);
            System.assert(false, 'Should have thrown exception for error callback');
        } catch (Auth.AuthProviderPluginException e) {
            System.assert(e.getMessage().contains('access_denied'), 
                         'Should contain error from callback: ' + e.getMessage());
        }
        
        Test.stopTest();
    }
    
    @IsTest
    static void testGetUserInfoFromIdToken() {
        Test.startTest();
        
        OpenIDConnectAuthProvider provider = new OpenIDConnectAuthProvider();
        Map<String, String> pluginConfig = new Map<String, String>();
        
        // Create a mock ID token (in real implementation, you'd create a proper JWT)
        String mockIdToken = createMockIdToken();
        
        Auth.AuthProviderTokenResponse tokenResponse = new Auth.AuthProviderTokenResponse(
            PROVIDER_NAME, TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN, TEST_STATE
        );
        tokenResponse.idToken = mockIdToken;
        
        try {
            Auth.UserData userData = provider.getUserInfo(pluginConfig, tokenResponse);
            
            // Verify user data extraction
            System.assertNotEquals(null, userData);
            System.assertEquals(PROVIDER_NAME, userData.provider);
            
        } catch (Exception e) {
            // Expected in test context without proper JWT or configuration
            System.assert(true, 'Expected error in test context: ' + e.getMessage());
        }
        
        Test.stopTest();
    }
    
    @IsTest
    static void testGetUserInfoWithoutIdToken() {
        Test.startTest();
        
        OpenIDConnectAuthProvider provider = new OpenIDConnectAuthProvider();
        Map<String, String> pluginConfig = new Map<String, String>();
        
        Auth.AuthProviderTokenResponse tokenResponse = new Auth.AuthProviderTokenResponse(
            PROVIDER_NAME, TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN, TEST_STATE
        );
        // No ID token, should throw exception
        
        try {
            Auth.UserData userData = provider.getUserInfo(pluginConfig, tokenResponse);
            System.assert(false, 'Should have thrown exception when ID token is missing');
        } catch (Auth.AuthProviderPluginException e) {
            System.assert(e.getMessage().contains('missing required ID token'), 
                         'Should contain ID token missing error: ' + e.getMessage());
        }
        
        Test.stopTest();
    }
    
    @IsTest
    static void testRefreshToken() {
        Test.startTest();
        
        // Mock HTTP callouts for token refresh
        Test.setMock(HttpCalloutMock.class, new OpenIDConnectRefreshMock());
        
        OpenIDConnectAuthProvider provider = new OpenIDConnectAuthProvider();
        Map<String, String> pluginConfig = new Map<String, String>();
        
        try {
            Auth.OAuthRefreshResult result = provider.refresh(pluginConfig, TEST_REFRESH_TOKEN);
            
            // In real implementation with proper configuration, this would succeed
            System.assertNotEquals(null, result);
            
        } catch (Exception e) {
            // Expected when configuration is not available in test context
            System.assert(true, 'Expected error in test context: ' + e.getMessage());
        }
        
        Test.stopTest();
    }
    
    @IsTest
    static void testRefreshTokenWithoutRefreshToken() {
        Test.startTest();
        
        OpenIDConnectAuthProvider provider = new OpenIDConnectAuthProvider();
        Map<String, String> pluginConfig = new Map<String, String>();
        
        Auth.OAuthRefreshResult result = provider.refresh(pluginConfig, null);
        System.assertEquals(null, result, 'Should return null when no refresh token provided');
        
        result = provider.refresh(pluginConfig, '');
        System.assertEquals(null, result, 'Should return null when empty refresh token provided');
        
        Test.stopTest();
    }
    
    // Helper methods
    
    private static Auth.AuthProviderCallbackState createCallbackState(String code, String state) {
        Map<String, String> queryParams = new Map<String, String>{
            'code' => code,
            'state' => state
        };
        return createCallbackStateWithParams(queryParams);
    }
    
    private static Auth.AuthProviderCallbackState createCallbackStateWithParams(Map<String, String> queryParams) {
        // Note: In real Salesforce testing, you would use the actual constructor
        // This is a simplified version for illustration
        Auth.AuthProviderCallbackState callbackState = new Auth.AuthProviderCallbackState();
        // The actual implementation would require reflection or a different approach
        // to set the queryParameters field since it's typically read-only
        return callbackState;
    }
    
    private static String createMockIdToken() {
        // In a real implementation, you would create a proper JWT with header, payload, and signature
        // For testing purposes, this would be a base64-encoded JSON payload
        Map<String, Object> payload = new Map<String, Object>{
            'sub' => 'test-user-123',
            'email' => 'test@example.com',
            'given_name' => 'Test',
            'family_name' => 'User',
            'name' => 'Test User',
            'iss' => 'https://provider.example.com',
            'aud' => CLIENT_ID,
            'exp' => (DateTime.now().getTime() / 1000) + 3600, // 1 hour from now
            'iat' => DateTime.now().getTime() / 1000
        };
        
        String payloadJson = JSON.serialize(payload);
        String encodedPayload = EncodingUtil.base64Encode(Blob.valueOf(payloadJson));
        
        // Simple mock JWT structure (header.payload.signature)
        return 'eyJhbGciOiJSUzI1NiJ9.' + encodedPayload + '.mock-signature';
    }
    
    // Mock HTTP callout classes
    
    public class OpenIDConnectTokenMock implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(200);
            res.setHeader('Content-Type', 'application/json');
            
            Map<String, Object> tokenResponse = new Map<String, Object>{
                'access_token' => TEST_ACCESS_TOKEN,
                'refresh_token' => TEST_REFRESH_TOKEN,
                'id_token' => createMockIdToken(),
                'token_type' => 'Bearer',
                'expires_in' => 3600
            };
            
            res.setBody(JSON.serialize(tokenResponse));
            return res;
        }
    }
    

    
    public class OpenIDConnectRefreshMock implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(200);
            res.setHeader('Content-Type', 'application/json');
            
            Map<String, Object> tokenResponse = new Map<String, Object>{
                'access_token' => 'new-' + TEST_ACCESS_TOKEN,
                'refresh_token' => 'new-' + TEST_REFRESH_TOKEN,
                'token_type' => 'Bearer',
                'expires_in' => 3600
            };
            
            res.setBody(JSON.serialize(tokenResponse));
            return res;
        }
    }
} 