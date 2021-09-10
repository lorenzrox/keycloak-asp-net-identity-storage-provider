package org.keycloak.storage.aspnet;

import org.keycloak.component.ComponentModel;
import org.keycloak.storage.UserStorageProviderModel;

public class AspNetIdentityProviderModel extends UserStorageProviderModel {
    public static final String DB_URL = "url";
    public static final String DB_USER = "user";
    public static final String DB_PASSWORD = "password";
    public static final String APPLICATION_NAME = "applicationName";
    public static final String VALIDATION_ALGORITHM = "validationAlgorithm";
    public static final String UPDATE_PROFILE_FIRST_LOGIN = "updateProfileFirstLogin";

    private transient String applicationName;
    private transient String dbUrl;
    private transient String dbUser;
    private transient String dbPassword;
    private transient Boolean updateProfileFirstLogin;
    private transient AspNetIdentityValidationAlgorithm validationAlgorithm;

    public AspNetIdentityProviderModel() {
        setProviderType(AspNetIdentityStorageProvider.class.getName());
    }

    public AspNetIdentityProviderModel(ComponentModel copy) {
        super(copy);
    }

    public String getDbUrl() {
        if (dbUrl == null) {
            dbUrl = getConfig().getFirst(DB_URL);
        }
        return dbUrl;
    }

    public void setDbUrl(String dbUrl) {
        this.dbUrl = dbUrl;
        getConfig().putSingle(DB_URL, dbUrl);
    }

    public String getDbUser() {
        if (dbUser == null) {
            dbUser = getConfig().getFirst(DB_USER);
        }
        return dbUser;
    }

    public void setDbUser(String dbUser) {
        this.dbUser = dbUser;
        getConfig().putSingle(DB_USER, dbUser);
    }

    public String getDbPassword() {
        if (dbPassword == null) {
            dbPassword = getConfig().getFirst(DB_PASSWORD);
        }
        return dbPassword;
    }

    public void setDbPassword(String dbPassword) {
        this.dbUser = dbPassword;
        getConfig().putSingle(DB_PASSWORD, dbPassword);
    }

    public String getApplicationName() {
        if (applicationName == null) {
            applicationName = getConfig().getFirst(APPLICATION_NAME);

            if (applicationName != null) {
                applicationName = applicationName.toLowerCase();
            }
        }
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
        getConfig().putSingle(APPLICATION_NAME, applicationName);
    }

    public AspNetIdentityValidationAlgorithm getValidationAlgorithm() {
        if (validationAlgorithm == null) {
            String val = getConfig().getFirst(VALIDATION_ALGORITHM);
            if (val == null) {
                validationAlgorithm = AspNetIdentityValidationAlgorithm.SHA1;
            } else {
                validationAlgorithm = AspNetIdentityValidationAlgorithm.valueOf(val);
            }
        }

        return validationAlgorithm;
    }

    public void setValidationAlgorithm(AspNetIdentityValidationAlgorithm validationAlgorithm) {
        this.validationAlgorithm = validationAlgorithm;
        getConfig().putSingle(VALIDATION_ALGORITHM, validationAlgorithm.name());
    }

    public boolean isUpdateProfileFirstLogin() {
        if (updateProfileFirstLogin == null) {
            String val = getConfig().getFirst(UPDATE_PROFILE_FIRST_LOGIN);
            if (val == null) {
                updateProfileFirstLogin = true;
            } else {
                updateProfileFirstLogin = Boolean.valueOf(val);
            }
        }
        return updateProfileFirstLogin;

    }

    public void setUpdateProfileFirstLogin(boolean updateProfileFirstLogin) {
        this.updateProfileFirstLogin = updateProfileFirstLogin;
        getConfig().putSingle(UPDATE_PROFILE_FIRST_LOGIN, Boolean.toString(updateProfileFirstLogin));
    }
}