package org.keycloak.storage.aspnet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.InMemoryUserAdapter;
import org.keycloak.storage.user.ImportedUserValidation;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

public class AspNetIdentityStorageProvider
        implements UserStorageProvider, UserRegistrationProvider, UserLookupProvider.Streams, UserQueryProvider.Streams,
        CredentialInputUpdater.Streams, ImportedUserValidation, CredentialInputValidator {
    private static final Logger logger = Logger.getLogger(AspNetIdentityStorageProvider.class);
    private static final int SALT_SIZE = 16;
    private final AspNetIdentityUserManager userManager = new AspNetIdentityUserManager();
    private final KeycloakSession session;
    private final AspNetIdentityProviderModel model;

    // https://github.com/microsoft/referencesource/blob/master/System.Web/Security/SQLMembershipProvider.cs
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
    // dbo.aspnet_Membership_GetPasswordWithFormat
    // dbo.aspnet_UsersInRoles_GetRolesForUser

    @FunctionalInterface
    interface SqlStatementFunction<T extends Statement> {
        T create(Connection connection) throws SQLException;
    }

    public AspNetIdentityStorageProvider(KeycloakSession session, AspNetIdentityProviderModel model) {
        this.session = session;
        this.model = model;
    }

    @Override
    public UserModel validate(RealmModel realm, UserModel user) {
        AspNetIdentityUser aspNetUser = loadAndValidateUser(realm, user);
        if (aspNetUser == null) {
            return null;
        }

        return proxy(realm, user, aspNetUser, false);
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        logger.debugf("getting user with id \"%s\" for realm \"%s\"", id, realm.getName());

        UserModel alreadyLoadedInSession = userManager.getManagedProxiedUser(id);
        if (alreadyLoadedInSession != null) {
            return alreadyLoadedInSession;
        }

        String externalId = StorageId.externalId(id);
        AspNetIdentityUser aspNetUser = loadAspNetUserById(realm, externalId);
        if (aspNetUser == null) {
            return null;
        }

        return importUserFromIdentity(realm, aspNetUser);
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        logger.debugf("getting user with username \"%s\" for realm \"%s\"", username, realm.getName());

        AspNetIdentityUser aspNetUser = loadAspNetUserByUserName(realm, username);
        if (aspNetUser == null) {
            return null;
        }

        UserModel user = session.userLocalStorage().getUserByUsername(realm, aspNetUser.getUserName());
        if (user != null) {
            if (aspNetUser.getId().equals(user.getFirstAttribute(AspNetIdentityConstants.ASPNET_IDENTITY_ID))) {
                return proxy(realm, user, aspNetUser, false);
            }

            throw new ModelDuplicateException("User with username '" + aspNetUser.getUserName()
                    + "' already exists in Keycloak. It conflicts with ASPNET Identity user with email '"
                    + aspNetUser.getEmail() + "'");
        }

        return importUserFromIdentity(realm, aspNetUser);
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        logger.debugf("getting user with email \"%s\" for realm \"%s\"", email, realm.getName());

        AspNetIdentityUser aspNetUser = loadAspNetUserByEmail(realm, email);
        if (aspNetUser == null) {
            return null;
        }

        UserModel user = session.userLocalStorage().getUserByUsername(realm, aspNetUser.getUserName());
        if (user != null) {
            if (aspNetUser.getId().equals(user.getFirstAttribute(AspNetIdentityConstants.ASPNET_IDENTITY_ID))) {
                return proxy(realm, user, aspNetUser, false);
            }

            throw new ModelDuplicateException("User with username '" + aspNetUser.getUserName()
                    + "' already exists in Keycloak. It conflicts with ASPNET Identity user with email '" + email
                    + "'");
        }

        return importUserFromIdentity(realm, aspNetUser);
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        logger.debugf("getting user count for realm \"%s\"", realm.getName());

        try (Connection connection = getConnection()) {
            try (PreparedStatement query = connection.prepareStatement(
                    "select count(*) from [dbo].[aspnet_Membership] m join [dbo].[aspnet_Users] u on m.UserId = u.UserId "
                            + "join[dbo].[aspnet_Applications] a on u.ApplicationId = a.ApplicationId "
                            + "where a.LoweredApplicationName = ?")) {
                query.setString(1, model.getApplicationName());

                try (ResultSet resultSet = query.executeQuery()) {
                    resultSet.next();
                    return resultSet.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Failed to query database.", ex);
        }
    }

    @Override
    public Stream<UserModel> getUsersStream(RealmModel realm, Integer firstResult, Integer maxResults) {
        logger.debugf("getting users for realm \"%s\" firstResult=%d, maxResults=%d", realm.getName(), firstResult,
                maxResults);

        return queryAsStream(realm, connection -> {
            String sql = "with Query as (select u.UserName, m.Email, m.Comment, m.IsApproved, m.CreateDate, u.UserId, m.IsLockedOut, "
                    + "row_number() over (order by u.UserName) as RowIndex "
                    + "from [dbo].[aspnet_Membership] m join [dbo].[aspnet_Users] u on m.UserId = u.UserId "
                    + "join [dbo].[aspnet_Applications] a on u.ApplicationId = a.ApplicationId "
                    + "where a.LoweredApplicationName = ?) select * from Query";

            boolean hasPagination = false;

            if (firstResult != null && firstResult > 0) {
                sql += " where RowIndex > ?";
                hasPagination = true;
            }

            if (maxResults != null && maxResults >= 0) {
                if (hasPagination) {
                    sql += " and RowIndex <= ?";
                } else {
                    sql += " where RowIndex <= ?";
                    hasPagination = true;
                }
            }

            sql += " order by u.UserName";

            PreparedStatement query = connection.prepareStatement(sql);

            try {
                query.setString(1, model.getApplicationName());

                if (hasPagination) {
                    int parameterOffset = 2;

                    if (firstResult != null && firstResult > 0) {
                        query.setInt(parameterOffset++, firstResult);

                        if (maxResults != null && maxResults >= 0) {
                            query.setInt(parameterOffset, firstResult + maxResults);
                        }
                    } else if (maxResults != null && maxResults >= 0) {
                        query.setInt(parameterOffset, maxResults);
                    }
                }
            } catch (SQLException ex) {
                query.close();
                throw ex;
            }

            return query;
        }, this::readUser);
    }

    @Override
    public int getUsersCount(RealmModel realm, String search) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put(UserModel.SEARCH, search);
        return getUsersCount(realm, attributes);
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult,
            Integer maxResults) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put(UserModel.SEARCH, search);
        return searchForUserStream(realm, attributes, firstResult, maxResults);
    }

    @Override
    public int getUsersCount(RealmModel realm, Map<String, String> params) {
        logger.debugf("getting user count for realm \"%s\"", realm.getName());

        String sql = "select count(*) from [dbo].[aspnet_Membership] m join [dbo].[aspnet_Users] u on m.UserId = u.UserId "
                + "join [dbo].[aspnet_Applications] a on u.ApplicationId = a.ApplicationId "
                + "where a.LoweredApplicationName = ?";

        List<String> parameters = new ArrayList<>(params.size());

        String userName = params.get(UserModel.USERNAME);
        if (userName != null) {
            sql += " and u.LoweredUserName = ?";
            parameters.add(userName.toLowerCase());
        }

        String email = params.get(UserModel.EMAIL);
        if (email != null) {
            sql += " and m.LoweredEmail = ?";
            parameters.add(email.toLowerCase());
        }

        String firstName = params.get(UserModel.FIRST_NAME);
        if (firstName != null) {
            sql += " and m.Comment like ?";
            parameters.add("%" + firstName + "%");
        }

        String lastName = params.get(UserModel.LAST_NAME);
        if (lastName != null) {
            sql += " and m.Comment like ?";
            parameters.add("%" + lastName + "%");
        }

        try (Connection connection = getConnection()) {
            try (PreparedStatement query = connection.prepareStatement(sql)) {
                query.setString(1, model.getApplicationName());

                for (int i = 0; i < parameters.size(); i++) {
                    query.setString(i + 2, parameters.get(i));
                }

                try (ResultSet resultSet = query.executeQuery()) {
                    resultSet.next();
                    return resultSet.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Failed to query database.", ex);
        }
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult,
            Integer maxResults) {
        logger.debugf("searching users for realm \"%s\" firstResult=%d, maxResults=%d", realm.getName(), firstResult,
                maxResults);

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

        return queryAsStream(realm, connection -> {
            String sql = "with Query as (select u.UserName, m.Email, m.Comment, m.IsApproved, m.CreateDate, u.UserId, m.IsLockedOut, "
                    + "row_number() over (order by u.UserName) as RowIndex "
                    + "from [dbo].[aspnet_Membership] m join [dbo].[aspnet_Users] u on m.UserId = u.UserId "
                    + "join [dbo].[aspnet_Applications] a on u.ApplicationId = a.ApplicationId "
                    + "where a.LoweredApplicationName = ?";

            List<String> parameters = new ArrayList<>(params.size());

            String userName = params.get(UserModel.USERNAME);
            if (userName != null) {
                sql += " and u.LoweredUserName = ?";
                parameters.add(userName.toLowerCase());
            }

            String email = params.get(UserModel.EMAIL);
            if (email != null) {
                sql += " and m.LoweredEmail = ?";
                parameters.add(email.toLowerCase());
            }

            String firstName = params.get(UserModel.FIRST_NAME);
            if (firstName != null) {
                sql += " and m.Comment like ?";
                parameters.add("%" + firstName + "%");
            }

            String lastName = params.get(UserModel.LAST_NAME);
            if (lastName != null) {
                sql += " and m.Comment like ?";
                parameters.add("%" + lastName + "%");
            }

            sql += ") select * from Query";

            boolean hasPagination = false;

            if (firstResult != null && firstResult > 0) {
                sql += " where RowIndex > ?";
                hasPagination = true;
            }

            if (maxResults != null && maxResults >= 0) {
                if (hasPagination) {
                    sql += " and RowIndex <= ?";
                } else {
                    sql += " where RowIndex <= ?";
                    hasPagination = true;
                }
            }

            sql += " order by UserName";

            PreparedStatement query = connection.prepareStatement(sql);

            try {
                query.setString(1, model.getApplicationName());

                int parameterOffset = 2;

                for (int i = 0; i < parameters.size(); i++) {
                    query.setString(parameterOffset++, parameters.get(i));
                }

                if (hasPagination) {
                    if (firstResult != null && firstResult > 0) {
                        query.setInt(parameterOffset++, firstResult);

                        if (maxResults != null && maxResults >= 0) {
                            query.setInt(parameterOffset, firstResult + maxResults);
                        }
                    } else if (maxResults != null && maxResults >= 0) {
                        query.setInt(parameterOffset, maxResults);
                    }
                }
            } catch (SQLException ex) {
                query.close();
                throw ex;
            }

            return query;
        }, this::readUser);
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
        logger.debugf("validating user's '%s' password. ", user.getUsername());

        if (!supportsCredentialType(credentialInput.getType())) {
            logger.info("credentialType:" + credentialInput.getType() + " not supported");
            return false;
        }

        if (!(credentialInput instanceof UserCredentialModel)) {
            logger.info("credential Input not instanceof userCredentialModel");
            return false;
        }

        AspNetIdentityStoredPassword storedPassword = loadUserPassword(realm, user.getUsername());
        if (storedPassword == null) {
            return false;
        }

        String encodedPassword = encodePassword(credentialInput.getChallengeResponse(), storedPassword.getFormat(),
                storedPassword.getSalt());
        return storedPassword.getPassword().equals(encodedPassword);
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) {
            logger.info("credentialType:" + input.getType() + " not supported");
            return false;
        }

        if (!(input instanceof UserCredentialModel)) {
            logger.info("credential Input not instanceof userCredentialModel");
            return false;
        }

        String password = input.getChallengeResponse();

        PolicyError error = session.getProvider(PasswordPolicyManagerProvider.class).validate(realm, user, password);
        if (error != null) {
            throw new ModelException(error.getMessage(), error.getParameters());
        }

        return updateUserPassword(realm, user.getUsername(), password);
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        return Stream.empty();
    }

    @Override
    public UserModel addUser(RealmModel realm, String userName) {
        UserModel user;
        if (model.isImportEnabled()) {
            user = session.userLocalStorage().addUser(realm, userName);
            user.setFederationLink(model.getId());
        } else {
            InMemoryUserAdapter adapter = new InMemoryUserAdapter(session, realm,
                    StorageId.keycloakId(model, userName));
            adapter.setUsername(userName);
            user = adapter;
        }

        AspNetIdentityUser aspNetUser = addAspNetUser(realm, user);
        if (aspNetUser == null) {
            return null;
        }

        user.setSingleAttribute(AspNetIdentityConstants.ASPNET_IDENTITY_ID, aspNetUser.getId());

        UserModel proxy = proxy(realm, user, aspNetUser, true);
        proxy.grantRole(realm.getDefaultRole());
        realm.getDefaultGroupsStream().forEach(proxy::joinGroup);
        realm.getRequiredActionProvidersStream().filter(RequiredActionProviderModel::isEnabled)
                .filter(RequiredActionProviderModel::isDefaultAction).map(RequiredActionProviderModel::getAlias)
                .forEachOrdered(proxy::addRequiredAction);

        return proxy;
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        String idAttribute = user.getFirstAttribute(AspNetIdentityConstants.ASPNET_IDENTITY_ID);
        if (idAttribute == null) {
            logger.warnf("User '%s' can't be deleted from ASPNET Identity as it doesn't exist here",
                    user.getUsername());
            return false;
        }

        userManager.removeManagedUserEntry(user.getId());

        return removeAspNetUserById(realm, idAttribute);
    }

    @Override
    public void close() {
    }

    private UserModel readUser(RealmModel realm, ResultSet resultSet) {

        try {
            String userName = resultSet.getString(1);
            UserModel local = session.userLocalStorage().getUserByUsername(realm, userName);
            if (local == null) {
                AspNetIdentityUser aspNetUser = new AspNetIdentityUser();
                aspNetUser.setUserName(userName);
                aspNetUser.setEmail(resultSet.getString(2));
                aspNetUser.setComment(resultSet.getString(3));
                aspNetUser.setIsApproved(resultSet.getBoolean(4));
                aspNetUser.setCreatedTimestamp(resultSet.getTimestamp(5).getTime());
                aspNetUser.setId(resultSet.getString(6));
                aspNetUser.setIsLockedOut(resultSet.getBoolean(7));

                // logger.debugf("loaded user %s", aspNetUser);

                local = importUserFromIdentity(realm, aspNetUser);
            }

            return local;
        } catch (SQLException ex) {
            throw new RuntimeException("Failed to query database.", ex);
        }
    }

    protected UserModel importUserFromIdentity(RealmModel realm, AspNetIdentityUser aspNetUser) {
        UserModel imported = null;
        if (model.isImportEnabled()) {
            // Search if there is already an existing user
            UserModel existingLocalUser = session.userLocalStorage().searchForUserByUserAttributeStream(realm,
                    AspNetIdentityConstants.ASPNET_IDENTITY_ID, aspNetUser.getId()).findFirst().orElse(null);
            if (existingLocalUser != null) {
                imported = existingLocalUser;
                // Need to evict the existing user from cache
                session.userCache().evict(realm, existingLocalUser);
            } else {
                imported = session.userLocalStorage().addUser(realm, aspNetUser.getUserName());
            }

            imported.setFederationLink(model.getId());
        } else {
            InMemoryUserAdapter adapter = new InMemoryUserAdapter(session, realm,
                    StorageId.keycloakId(model, aspNetUser.getUserName()));
            adapter.addDefaults();
            imported = adapter;
        }

        imported.setSingleAttribute(AspNetIdentityConstants.ASPNET_IDENTITY_ID, aspNetUser.getId());

        String email = aspNetUser.getEmail();
        if (email != null) {
            // imported.setEmail(email);
            // imported.setEmailVerified(aspNetUser.getIsApproved());
        }

        String comment = aspNetUser.getComment();
        if (comment != null) {
            int spaceIndex = comment.lastIndexOf(' ');
            if (spaceIndex > -1) {
                imported.setFirstName(comment.substring(0, spaceIndex).trim());
                imported.setLastName(comment.substring(spaceIndex).trim());
            } else {
                imported.setFirstName(comment);
            }
        }

        imported.setCreatedTimestamp(aspNetUser.getCreatedTimestamp());
        imported.setEnabled(!aspNetUser.getIsLockedOut());

        if (model.isUpdateProfileFirstLogin()) {
            imported.addRequiredAction(UserModel.RequiredAction.UPDATE_PROFILE);
        }

        logger.debugf(
                "Imported new user from ASPNET Identity to Keycloak DB. Username: [%s], Email: [%s], ASPNET_IDENTITY_ID: [%s]",
                imported.getUsername(), imported.getEmail(), aspNetUser.getId());

        return proxy(realm, imported, aspNetUser, false);
    }

    protected UserModel proxy(RealmModel realm, UserModel local, AspNetIdentityUser aspNetUser, boolean newUser) {
        UserModel existing = userManager.getManagedProxiedUser(local.getId());
        if (existing != null) {
            return existing;
        }

        userManager.setManagedProxiedUser(local, aspNetUser);
        return local;
    }

    protected AspNetIdentityUser loadAndValidateUser(RealmModel realm, UserModel local) {
        AspNetIdentityUser existing = userManager.getManagedAspNetUser(local.getId());
        if (existing != null) {
            return existing;
        }

        String idAttribute = local.getFirstAttribute(AspNetIdentityConstants.ASPNET_IDENTITY_ID);
        return loadAspNetUserById(realm, idAttribute);
    }

    protected AspNetIdentityUser loadAspNetUserById(RealmModel realm, String id) {
        try (Connection connection = getConnection()) {
            try (CallableStatement storedProcedure = connection
                    .prepareCall("{call dbo.aspnet_Membership_GetUserByUserId(?,?)}")) {
                storedProcedure.setString(1, id);
                storedProcedure.setTimestamp(2, Timestamp.from(Instant.now()));

                try (ResultSet resultSet = storedProcedure.executeQuery()) {
                    if (resultSet.next()) {
                        AspNetIdentityUser aspNetUser = new AspNetIdentityUser();
                        aspNetUser.setId(id);
                        aspNetUser.setEmail(resultSet.getString(1));
                        aspNetUser.setComment(resultSet.getString(3));
                        aspNetUser.setIsApproved(resultSet.getBoolean(4));
                        aspNetUser.setCreatedTimestamp(resultSet.getTimestamp(5).getTime());
                        aspNetUser.setUserName(resultSet.getString(9));
                        aspNetUser.setIsLockedOut(resultSet.getBoolean(10));

                        // logger.debugf("loaded user %s", aspNetUser);

                        return aspNetUser;
                    } else {
                        return null;
                    }
                }
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Failed to query database.", ex);
        }
    }

    protected AspNetIdentityUser loadAspNetUserByEmail(RealmModel realm, String email) {
        try (Connection connection = getConnection()) {
            try (CallableStatement storedProcedure = connection
                    .prepareCall("{call dbo.aspnet_Membership_GetUserByEmail(?,?)}")) {
                storedProcedure.setString(1, model.getApplicationName());
                storedProcedure.setString(2, email);

                try (ResultSet resultSet = storedProcedure.executeQuery()) {
                    if (resultSet.next()) {
                        return loadAspNetUserByUserName(connection, realm, resultSet.getString(1));
                    } else {
                        return null;
                    }
                }
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Failed to query database.", ex);
        }
    }

    protected AspNetIdentityUser loadAspNetUserByUserName(RealmModel realm, String userName) {
        try (Connection connection = getConnection()) {
            return loadAspNetUserByUserName(connection, realm, userName);
        } catch (SQLException ex) {
            throw new RuntimeException("Failed to query database.", ex);
        }
    }

    private AspNetIdentityUser loadAspNetUserByUserName(Connection connection, RealmModel realm, String userName)
            throws SQLException {
        try (CallableStatement storedProcedure = connection
                .prepareCall("{call dbo.aspnet_Membership_GetUserByName(?,?,?)}")) {
            storedProcedure.setString(1, model.getApplicationName());
            storedProcedure.setString(2, userName);
            storedProcedure.setTimestamp(3, Timestamp.from(Instant.now()));

            try (ResultSet resultSet = storedProcedure.executeQuery()) {
                if (resultSet.next()) {
                    AspNetIdentityUser aspNetUser = new AspNetIdentityUser();
                    aspNetUser.setUserName(userName);
                    aspNetUser.setEmail(resultSet.getString(1));
                    aspNetUser.setComment(resultSet.getString(3));
                    aspNetUser.setIsApproved(resultSet.getBoolean(4));
                    aspNetUser.setCreatedTimestamp(resultSet.getTimestamp(5).getTime());
                    aspNetUser.setId(resultSet.getString(9));
                    aspNetUser.setIsLockedOut(resultSet.getBoolean(10));

                    // logger.debugf("loaded user %s", aspNetUser);

                    return aspNetUser;
                } else {
                    return null;
                }
            }
        }
    }

    protected AspNetIdentityStoredPassword loadUserPassword(RealmModel realm, String userName) {
        try (Connection connection = getConnection()) {
            return loadUserPassword(connection, realm, userName);
        } catch (SQLException ex) {
            throw new RuntimeException("Failed to query database.", ex);
        }
    }

    private AspNetIdentityStoredPassword loadUserPassword(Connection connection, RealmModel realm, String userName)
            throws SQLException {
        try (CallableStatement storedProcedure = connection
                .prepareCall("{call dbo.aspnet_Membership_GetPasswordWithFormat(?,?,?,?)}")) {
            storedProcedure.setString(1, model.getApplicationName());
            storedProcedure.setString(2, userName);
            storedProcedure.setBoolean(3, true);
            storedProcedure.setTimestamp(4, Timestamp.from(Instant.now()));

            try (ResultSet resultSet = storedProcedure.executeQuery()) {
                if (resultSet.next()) {
                    AspNetIdentityStoredPassword password = new AspNetIdentityStoredPassword();
                    password.setPassword(resultSet.getString(1));
                    password.setFormat(resultSet.getInt(2));
                    password.setSalt(resultSet.getString(3));

                    //logger.debugf("loaded stored password %s", password);

                    return password;
                } else {
                    return null;
                }
            }
        }
    }

    protected boolean updateUserPassword(RealmModel realm, String userName, String newPassword) {
        try (Connection connection = getConnection()) {
            AspNetIdentityStoredPassword storedPassword = loadUserPassword(connection, realm, userName);
            if (storedPassword == null) {
                return false;
            }

            String encodedPassword = encodePassword(newPassword, storedPassword.getFormat(), storedPassword.getSalt());

            try (CallableStatement storedProcedure = connection
                    .prepareCall("{call dbo.aspnet_Membership_SetPassword(?,?,?,?,?,?)}")) {
                storedProcedure.setString(1, model.getApplicationName());
                storedProcedure.setString(2, userName);
                storedProcedure.setString(3, encodedPassword);
                storedProcedure.setString(4, storedPassword.getSalt());
                storedProcedure.setTimestamp(5, Timestamp.from(Instant.now()));
                storedProcedure.setInt(6, storedPassword.getFormat());
         
                storedProcedure.executeUpdate();

                return true;
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Failed to update database.", ex);
        }
    }

    protected List<String> loadUserRoles(RealmModel realm, String userName) {
        try (Connection connection = getConnection()) {
            try (CallableStatement storedProcedure = connection
                    .prepareCall("{call dbo.aspnet_UsersInRoles_GetRolesForUser(?,?)}")) {
                storedProcedure.setString(1, model.getApplicationName());
                storedProcedure.setString(2, userName);

                try (ResultSet resultSet = storedProcedure.executeQuery()) {
                    List<String> roles = new ArrayList<>();

                    while (resultSet.next()) {
                        roles.add(resultSet.getString(1));
                    }

                    return roles;
                }
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Failed to query database.", ex);
        }
    }

    protected AspNetIdentityUser addAspNetUser(RealmModel realm, UserModel user) {
        // TODO: implement
        return null;
    }

    protected boolean removeAspNetUserById(RealmModel realm, String id) {
        // TODO: implement
        return false;
    }

    private Connection getConnection() {
        try {
            return DriverManager.getConnection(model.getDbUrl(), model.getDbUser(), model.getDbPassword());
        } catch (Exception e) {
            throw new RuntimeException("Failed to connect to database", e);
        }
    }

    private String generatePassword() {
        // TODO: implement
        return null;
    }

    private <T> Stream<T> queryAsStream(RealmModel realm, SqlStatementFunction<PreparedStatement> statement,
            BiFunction<RealmModel, ResultSet, T> mapper) {
        Connection connection = getConnection();

        try {
            try {
                PreparedStatement query = statement.create(connection);

                try {
                    final ResultSet resultSet = query.executeQuery();

                    return StreamSupport
                            .stream(new Spliterators.AbstractSpliterator<T>(Long.MAX_VALUE, Spliterator.ORDERED) {
                                @Override
                                public boolean tryAdvance(Consumer<? super T> action) {
                                    try {
                                        if (!resultSet.next()) {
                                            return false;
                                        }

                                        action.accept(mapper.apply(realm, resultSet));
                                    } catch (SQLException e) {
                                        throw new RuntimeException(e.getMessage(), e);
                                    }
                                    return true;
                                }
                            }, false).onClose(() -> {
                                try {
                                    try {
                                        try {
                                            resultSet.close();
                                        } finally {
                                            query.close();
                                        }
                                    } finally {
                                        connection.close();
                                    }
                                } catch (Exception ex) {
                                }
                            });
                } catch (SQLException ex) {
                    query.close();
                    throw ex;
                }
            } catch (SQLException ex) {
                connection.close();
                throw ex;
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Failed to query database.", ex);
        }
    }

    private String encodePassword(String password, int passwordFormat, String salt) {
        // Plain password
        if (passwordFormat == 0) {
            return password;
        }

        try {
            if (passwordFormat != 1) {
                throw new UnsupportedOperationException("Password format not supported");
            }

            byte[] passwordBuffer = password.getBytes(StandardCharsets.UTF_16LE);
            byte[] resultBuffer = getHashAlgorithm(salt).computeHash(passwordBuffer);
            return Base64.encodeBytes(resultBuffer);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode password", e);
        }
    }

    private String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte randBytes[] = new byte[SALT_SIZE];
        random.nextBytes(randBytes);

        return Base64.encodeBytes(randBytes);
    }

    private HashAlgorithm getHashAlgorithm(String salt)
            throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        switch (model.getValidationAlgorithm()) {
            case MD5:
                return new DigestHashAlgorithm("MD5", salt);
            case HMACSHA256:
                return new KeyedHashAlgorithm("HmacSHA256", salt, 64);
            case HMACSHA384:
                return new KeyedHashAlgorithm("HmacSHA384", salt, 128);
            case HMACSHA512:
                return new KeyedHashAlgorithm("HmacSHA512", salt, 128);
            default: {
                return new DigestHashAlgorithm("SHA-1", salt);
            }
        }
    }

    private interface HashAlgorithm {
        byte[] computeHash(byte[] input);
    }

    private static class DigestHashAlgorithm implements HashAlgorithm {
        private final MessageDigest digest;
        private final byte[] saltBuffer;

        DigestHashAlgorithm(String algorithm, String salt) throws NoSuchAlgorithmException, IOException {
            digest = MessageDigest.getInstance(algorithm);
            saltBuffer = Base64.decode(salt);
        }

        @Override
        public byte[] computeHash(byte[] input) {
            byte[] buffer = new byte[saltBuffer.length + input.length];
            System.arraycopy(saltBuffer, 0, buffer, 0, saltBuffer.length);
            System.arraycopy(input, 0, buffer, saltBuffer.length, input.length);
            return digest.digest(buffer);
        }
    }

    private static class KeyedHashAlgorithm implements HashAlgorithm {
        private final Mac mac;

        KeyedHashAlgorithm(String algorithm, String salt, int keySize)
                throws NoSuchAlgorithmException, InvalidKeyException, IOException {
            mac = Mac.getInstance(algorithm);
            mac.init(getKey(algorithm, salt, keySize));
        }

        @Override
        public byte[] computeHash(byte[] input) {
            return mac.doFinal(input);
        }

        private static SecretKeySpec getKey(String algorithm, String salt, int keySize) throws IOException {
            byte[] saltBuffer = Base64.decode(salt);

            if (saltBuffer.length < keySize) {
                byte[] keyBuffer = new byte[keySize];

                for (int iter = 0; iter < keySize;) {
                    int len = Math.min(saltBuffer.length, keySize - iter);
                    System.arraycopy(saltBuffer, 0, keyBuffer, iter, len);
                    iter += len;
                }

                saltBuffer = keyBuffer;
            } else if (saltBuffer.length > keySize) {
                saltBuffer = Arrays.copyOfRange(saltBuffer, 0, keySize);
            }

            return new SecretKeySpec(saltBuffer, algorithm);
        }
    }
}
