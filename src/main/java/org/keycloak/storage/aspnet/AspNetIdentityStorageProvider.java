package org.keycloak.storage.aspnet;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import org.keycloak.common.util.Base64;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.user.ImportedUserValidation;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

public class AspNetIdentityStorageProvider
        implements UserStorageProvider, UserRegistrationProvider, UserLookupProvider.Streams, UserQueryProvider.Streams,
        CredentialInputUpdater.Streams, ImportedUserValidation, CredentialInputValidator {
    private static final int SALT_SIZE = 16;
    private final KeycloakSession session;
    private final UserStorageProviderModel model;

    // https://github.com/microsoft/referencesource/blob/master/System.Web/Security/SQLMembershipProvider.cs
    // https://docs.microsoft.com/it-it/sql/connect/jdbc/using-basic-data-types?view=sql-server-ver15

    // dbo.aspnet_Membership_CreateUser
    // dbo.aspnet_Membership_SetPassword
    // dbo.aspnet_Membership_ResetPassword
    // dbo.aspnet_Membership_UpdateUser
    // dbo.aspnet_Membership_UnlockUser
    // dbo.aspnet_Membership_GetUserByUserId
    // dbo.aspnet_Membership_GetUserByName
    // dbo.aspnet_Membership_GetUserByEmail
    // dbo.aspnet_Users_DeleteUser
    // dbo.aspnet_Membership_GetAllUsers
    // dbo.aspnet_Membership_FindUsersByEmail
    // dbo.aspnet_Membership_FindUsersByName

    public AspNetIdentityStorageProvider(KeycloakSession session, UserStorageProviderModel model) {
        this.session = session;
        this.model = model;
    }

    @Override
    public UserModel validate(RealmModel realm, UserModel user) {
        // TODO: implement
        return null;
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        try (Connection connection = getConnection()) {
            try (CallableStatement storedProcedure = connection
                    .prepareCall("call [dbo].[aspnet_Membership_GetUserByUserId] (?,?)")) {
                storedProcedure.setString(0, id);
                storedProcedure.setTimestamp(1, Timestamp.from(Instant.now()));

                try (ResultSet resultSet = storedProcedure.executeQuery()) {
                    if (resultSet.next()) {
                        String email = resultSet.getString(0);
                        String comment = resultSet.getString(2);
                        Boolean isApproved = resultSet.getBoolean(3);
                        Timestamp createdTimeStamp = resultSet.getTimestamp(4);
                        String userName = resultSet.getString(8);
                        Boolean isLockedOut = resultSet.getBoolean(9);

                        // TODO: read user
                        return null;
                    } else {
                        return null;
                    }
                }
            }
        } catch (SQLException cause) {
            throw new RuntimeException("Failed to query database.", cause);
        }
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        try (Connection connection = getConnection()) {
            return getUserByUsername(connection, realm, username);
        } catch (SQLException cause) {
            throw new RuntimeException("Failed to query database.", cause);
        }
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        try (Connection connection = getConnection()) {
            try (CallableStatement storedProcedure = connection
                    .prepareCall("call [dbo].[aspnet_Membership_GetUserByEmail] (?,?)")) {
                storedProcedure.setString(0, "appname");
                storedProcedure.setString(1, email);

                try (ResultSet resultSet = storedProcedure.executeQuery()) {
                    if (resultSet.next()) {
                        return getUserByUsername(connection, realm, resultSet.getString(0));
                    } else {
                        return null;
                    }
                }
            }
        } catch (SQLException cause) {
            throw new RuntimeException("Failed to query database.", cause);
        }
    }

    @Override
    public Stream<UserModel> getUsersStream(RealmModel realm, Integer firstResult, Integer maxResults) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult,
            Integer maxResults) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put(UserModel.SEARCH, search);
        return searchForUserStream(realm, attributes, firstResult, maxResults);
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult,
            Integer maxResults) {
        String search = params.get(UserModel.SEARCH);
        if (search != null) {
            int spaceIndex = search.lastIndexOf(' ');
            if (spaceIndex > -1) {
                String firstName = search.substring(0, spaceIndex).trim();
                String lastName = search.substring(spaceIndex).trim();
                params.put(UserModel.FIRST_NAME, firstName);
                params.put(UserModel.LAST_NAME, lastName);
            } else if (search.indexOf('@') > -1) {
                params.put(UserModel.USERNAME, search.trim().toLowerCase());
                params.put(UserModel.EMAIL, search.trim().toLowerCase());
            } else {
                params.put(UserModel.LAST_NAME, search.trim());
                params.put(UserModel.USERNAME, search.trim().toLowerCase());
            }
        }

        // TODO: implement
        return null;
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult,
            Integer maxResults) {
        return null;
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        return null;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(PasswordCredentialModel.TYPE);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel) || !PasswordCredentialModel.TYPE.equals(input.getType())) {
            return false;
        }

        UserCredentialModel credentials = (UserCredentialModel) input;

        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        return Stream.empty();
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void close() {
    }

    private UserModel getUserByUsername(Connection connection, RealmModel realm, String username) throws SQLException {
        try (CallableStatement storedProcedure = connection
                .prepareCall("call [dbo].[aspnet_Membership_GetUserByName] (?,?,?)")) {
            storedProcedure.setString(0, "appname");
            storedProcedure.setString(1, username);
            storedProcedure.setTimestamp(2, Timestamp.from(Instant.now()));

            try (ResultSet resultSet = storedProcedure.executeQuery()) {
                if (resultSet.next()) {
                    String email = resultSet.getString(0);
                    String comment = resultSet.getString(2);
                    Boolean isApproved = resultSet.getBoolean(3);
                    Timestamp createdTimeStamp = resultSet.getTimestamp(4);
                    String userId = resultSet.getString(8);
                    Boolean isLockedOut = resultSet.getBoolean(9);

                    // TODO: read user
                    return null;
                } else {
                    return null;
                }
            }
        }
    }

    private Connection getConnection() {
        try {
            return null;
        } catch (Exception e) {
            throw new RuntimeException("Failed to connect to database", e);
        }
    }

    private String GeneratePassword() {
        return null;
    }

    private static String GenerateSalt() {
        try {
            SecureRandom random = new SecureRandom();
            byte randBytes[] = new byte[SALT_SIZE];
            random.nextBytes(randBytes);

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(randBytes);

            return Base64.encodeBytes(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate password salt", e);
        }
    }
}
