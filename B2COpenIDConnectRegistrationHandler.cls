public class B2COpenIDConnectRegistrationHandler implements Auth.RegistrationHandler {
    
    /* --------------------------------------------------------------------- */
    /*  JIT User Provisioning - Create or Update User                       */
    /* --------------------------------------------------------------------- */
    public User createUser(Id portalId, Auth.UserData data) {
        System.debug('B2C OIDC Registration Handler - Creating user for: ' + data.email);
        
        // Validate required data
        if (String.isBlank(data.identifier)) {
            throw new Auth.AuthProviderPluginException('Cannot create user: identifier is required');
        }
        
        if (String.isBlank(data.email)) {
            throw new Auth.AuthProviderPluginException('Cannot create user: email is required');
        }
        
        // Check if user already exists
        User existingUser = findExistingUser(data);
        if (existingUser != null) {
            System.debug('User already exists, updating: ' + existingUser.Id);
            return updateUser(existingUser, data);
        }
        
        // Create new user
        User newUser = buildNewUser(data, portalId);
        
        try {
            insert newUser;
            System.debug('Successfully created user: ' + newUser.Id);
            return newUser;
        } catch (DmlException e) {
            System.debug('Failed to create user: ' + e.getMessage());
            throw new Auth.AuthProviderPluginException('Failed to create user: ' + e.getMessage());
        }
    }
    
    /* --------------------------------------------------------------------- */
    /*  Update Existing User                                                 */
    /* --------------------------------------------------------------------- */
    public void updateUser(Id userId, Id portalId, Auth.UserData data) {
        System.debug('B2C OIDC Registration Handler - Updating user: ' + userId);
        
        try {
            User userToUpdate = [SELECT Id, FederationIdentifier, Email, FirstName, LastName, 
                                      Username, IsActive
                               FROM User 
                               WHERE Id = :userId 
                               LIMIT 1];
            
            User updatedUser = updateUser(userToUpdate, data);
            update updatedUser;
            
            System.debug('Successfully updated user: ' + userId);
        } catch (QueryException e) {
            System.debug('User not found for update: ' + userId);
            throw new Auth.AuthProviderPluginException('User not found: ' + userId);
        } catch (DmlException e) {
            System.debug('Failed to update user: ' + e.getMessage());
            throw new Auth.AuthProviderPluginException('Failed to update user: ' + e.getMessage());
        }
    }
    
    /* --------------------------------------------------------------------- */
    /*  Find Existing User by Federation Identifier or Email                */
    /* --------------------------------------------------------------------- */
    private User findExistingUser(Auth.UserData data) {
        List<User> existingUsers = new List<User>();
        
        // First try to find by FederationIdentifier
        if (String.isNotBlank(data.identifier)) {
            existingUsers = [SELECT Id, FederationIdentifier, Email, FirstName, LastName, 
                                  Username, IsActive
                           FROM User 
                           WHERE FederationIdentifier = :data.identifier 
                           AND IsActive = true
                           LIMIT 1];
        }
        
        // If not found by FederationIdentifier, try by email
        if (existingUsers.isEmpty() && String.isNotBlank(data.email)) {
            existingUsers = [SELECT Id, FederationIdentifier, Email, FirstName, LastName, 
                                  Username, IsActive
                           FROM User 
                           WHERE Email = :data.email 
                           AND IsActive = true
                           LIMIT 1];
        }
        
        return existingUsers.isEmpty() ? null : existingUsers[0];
    }
    
    /* --------------------------------------------------------------------- */
    /*  Build New User Record                                                */
    /* --------------------------------------------------------------------- */
    private User buildNewUser(Auth.UserData data, Id portalId) {
        User newUser = new User();
        
        // Required fields
        newUser.FederationIdentifier = data.identifier;
        newUser.Email = data.email;
        newUser.Username = generateUniqueUsername(data.email);
        newUser.LastName = String.isNotBlank(data.lastName) ? data.lastName : extractLastNameFromEmail(data.email);
        newUser.FirstName = String.isNotBlank(data.firstName) ? data.firstName : extractFirstNameFromEmail(data.email);
        
        // Optional fields
        if (String.isNotBlank(data.fullName)) {
            // Split full name if individual names not provided
            if (String.isBlank(data.firstName) || String.isBlank(data.lastName)) {
                List<String> nameParts = data.fullName.split(' ', 2);
                if (nameParts.size() > 0 && String.isBlank(data.firstName)) {
                    newUser.FirstName = nameParts[0];
                }
                if (nameParts.size() > 1 && String.isBlank(data.lastName)) {
                    newUser.LastName = nameParts[1];
                }
            }
        }
        
        // System fields
        newUser.Alias = generateAlias(newUser.FirstName, newUser.LastName);
        newUser.EmailEncodingKey = 'UTF-8';
        newUser.LanguageLocaleKey = 'en_US';
        newUser.LocaleSidKey = 'en_US';
        newUser.TimeZoneSidKey = 'America/Chicago';
        newUser.IsActive = true;
        
        // Profile assignment
        newUser.ProfileId = getDefaultProfileId(portalId);
        
        // Custom fields (add as needed)
        // newUser.Department = 'External Users';
        // newUser.CompanyName = 'B2C Customer';
        
        return newUser;
    }
    
    /* --------------------------------------------------------------------- */
    /*  Update User with Latest Data                                         */
    /* --------------------------------------------------------------------- */
    private User updateUser(User existingUser, Auth.UserData data) {
        // Update FederationIdentifier if it was missing
        if (String.isBlank(existingUser.FederationIdentifier) && String.isNotBlank(data.identifier)) {
            existingUser.FederationIdentifier = data.identifier;
        }
        
        // Update email if different
        if (String.isNotBlank(data.email) && !data.email.equals(existingUser.Email)) {
            existingUser.Email = data.email;
        }
        
        // Update names if provided and different
        if (String.isNotBlank(data.firstName) && !data.firstName.equals(existingUser.FirstName)) {
            existingUser.FirstName = data.firstName;
        }
        
        if (String.isNotBlank(data.lastName) && !data.lastName.equals(existingUser.LastName)) {
            existingUser.LastName = data.lastName;
        }
        
        // Ensure user is active
        if (!existingUser.IsActive) {
            existingUser.IsActive = true;
        }
        
        return existingUser;
    }
    
    /* --------------------------------------------------------------------- */
    /*  Generate Unique Username                                             */
    /* --------------------------------------------------------------------- */
    private String generateUniqueUsername(String email) {
        // Start with email as base username
        String baseUsername = email;
        String uniqueUsername = baseUsername;
        Integer counter = 1;
        
        // Check for existing usernames and append counter if needed
        while (usernameExists(uniqueUsername)) {
            uniqueUsername = baseUsername + '.' + counter;
            counter++;
            
            // Prevent infinite loop
            if (counter > 1000) {
                uniqueUsername = baseUsername + '.' + System.currentTimeMillis();
                break;
            }
        }
        
        return uniqueUsername;
    }
    
    /* --------------------------------------------------------------------- */
    /*  Check if Username Already Exists                                     */
    /* --------------------------------------------------------------------- */
    private Boolean usernameExists(String username) {
        List<User> existingUsers = [SELECT Id FROM User WHERE Username = :username LIMIT 1];
        return !existingUsers.isEmpty();
    }
    
    /* --------------------------------------------------------------------- */
    /*  Generate User Alias                                                  */
    /* --------------------------------------------------------------------- */
    private String generateAlias(String firstName, String lastName) {
        String alias = '';
        
        if (String.isNotBlank(firstName)) {
            alias += firstName.substring(0, 1);
        }
        
        if (String.isNotBlank(lastName)) {
            alias += lastName.length() >= 4 ? lastName.substring(0, 4) : lastName;
        }
        
        // Ensure alias is not empty and not too long
        if (String.isBlank(alias)) {
            alias = 'User';
        }
        
        // Alias max length is 8 characters
        if (alias.length() > 8) {
            alias = alias.substring(0, 8);
        }
        
        return alias;
    }
    
    /* --------------------------------------------------------------------- */
    /*  Get Default Profile ID                                               */
    /* --------------------------------------------------------------------- */
    private Id getDefaultProfileId(Id portalId) {
        // For Experience Cloud sites (portalId provided)
        if (portalId != null) {
            try {
                // Get the default profile for the community
                List<Profile> communityProfiles = [SELECT Id FROM Profile 
                                                 WHERE Name = 'Customer Community User' 
                                                 OR Name = 'Partner Community User'
                                                 OR Name = 'Customer Community Plus User'
                                                 LIMIT 1];
                if (!communityProfiles.isEmpty()) {
                    return communityProfiles[0].Id;
                }
            } catch (QueryException e) {
                System.debug('Community profile not found, falling back to standard user');
            }
        }
        
        // For standard Salesforce org (no portalId)
        try {
            List<Profile> standardProfiles = [SELECT Id FROM Profile 
                                            WHERE Name = 'Standard User' 
                                            OR Name = 'Chatter Free User'
                                            LIMIT 1];
            if (!standardProfiles.isEmpty()) {
                return standardProfiles[0].Id;
            }
        } catch (QueryException e) {
            System.debug('Standard profile not found');
        }
        
        // Fallback - get any profile (should not happen in normal orgs)
        List<Profile> anyProfile = [SELECT Id FROM Profile WHERE UserType = 'Standard' LIMIT 1];
        if (!anyProfile.isEmpty()) {
            return anyProfile[0].Id;
        }
        
        throw new Auth.AuthProviderPluginException('No suitable profile found for user creation');
    }
    
    /* --------------------------------------------------------------------- */
    /*  Extract First Name from Email                                        */
    /* --------------------------------------------------------------------- */
    private String extractFirstNameFromEmail(String email) {
        if (String.isBlank(email) || !email.contains('@')) {
            return 'User';
        }
        
        String localPart = email.split('@')[0];
        
        // Handle common email patterns
        if (localPart.contains('.')) {
            String[] parts = localPart.split('\\.');
            return parts[0].substring(0, 1).toUpperCase() + parts[0].substring(1).toLowerCase();
        }
        
        if (localPart.contains('_')) {
            String[] parts = localPart.split('_');
            return parts[0].substring(0, 1).toUpperCase() + parts[0].substring(1).toLowerCase();
        }
        
        // Default to first part of email
        return localPart.substring(0, 1).toUpperCase() + localPart.substring(1).toLowerCase();
    }
    
    /* --------------------------------------------------------------------- */
    /*  Extract Last Name from Email                                         */
    /* --------------------------------------------------------------------- */
    private String extractLastNameFromEmail(String email) {
        if (String.isBlank(email) || !email.contains('@')) {
            return 'User';
        }
        
        String localPart = email.split('@')[0];
        
        // Handle common email patterns
        if (localPart.contains('.')) {
            String[] parts = localPart.split('\\.');
            if (parts.size() > 1) {
                String lastName = parts[parts.size() - 1];
                return lastName.substring(0, 1).toUpperCase() + lastName.substring(1).toLowerCase();
            }
        }
        
        if (localPart.contains('_')) {
            String[] parts = localPart.split('_');
            if (parts.size() > 1) {
                String lastName = parts[parts.size() - 1];
                return lastName.substring(0, 1).toUpperCase() + lastName.substring(1).toLowerCase();
            }
        }
        
        // Default fallback
        return 'User';
    }
} 