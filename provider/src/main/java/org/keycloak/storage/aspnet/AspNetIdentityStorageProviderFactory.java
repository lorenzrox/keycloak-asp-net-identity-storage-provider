package org.keycloak.storage.aspnet;

import java.util.List;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;

public class AspNetIdentityStorageProviderFactory implements UserStorageProviderFactory<AspNetIdentityStorageProvider> {
    private static final List<ProviderConfigProperty> configProperties;
    public static final String PROVIDER_NAME = AspNetIdentityConstants.ASPNET_PROVIDER;

    static {
        configProperties = getConfigProps();
    }

    @Override
    public AspNetIdentityStorageProvider create(KeycloakSession session, ComponentModel model) {
        AspNetIdentityProviderModel providerModel = new AspNetIdentityProviderModel(model);
        if (providerModel.getApplicationName() == null || providerModel.getDbUrl() == null
                || providerModel.getDbUser() == null || providerModel.getDbPassword() == null) {
            return null;
        }
        
        return new AspNetIdentityStorageProvider(session, providerModel);
    }

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    private static List<ProviderConfigProperty> getConfigProps() {
        return ProviderConfigurationBuilder.create().property().name(AspNetIdentityProviderModel.DB_URL)
                .label(AspNetIdentityConstants.DB_URL_LABEL).helpText(AspNetIdentityConstants.DB_URL_HELP_TEXT)
                .type(ProviderConfigProperty.STRING_TYPE).add().property().name(AspNetIdentityProviderModel.DB_USER)
                .label(AspNetIdentityConstants.DB_USER_LABEL).helpText(AspNetIdentityConstants.DB_USER_HELP_TEXT)
                .type(ProviderConfigProperty.STRING_TYPE).add().property().name(AspNetIdentityProviderModel.DB_PASSWORD)
                .label(AspNetIdentityConstants.DB_PASSWORD_LABEL)
                .helpText(AspNetIdentityConstants.DB_PASSWORD_HELP_TEXT).type(ProviderConfigProperty.PASSWORD).add()
                .property().name(AspNetIdentityProviderModel.APPLICATION_NAME)
                .label(AspNetIdentityConstants.APPLICATION_NAME_LABEL)
                .helpText(AspNetIdentityConstants.APPLICATION_NAME_HELP_TEXT).type(ProviderConfigProperty.STRING_TYPE)
                .add().property().name(UserStorageProviderModel.IMPORT_ENABLED)
                .label(AspNetIdentityConstants.IMPORT_ENABLED_LABEL)
                .helpText(AspNetIdentityConstants.IMPORT_ENABLED_HELP_TEXT).type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true").add().property().name(AspNetIdentityProviderModel.UPDATE_PROFILE_FIRST_LOGIN)
                .label(AspNetIdentityConstants.UPDATE_PROFILE_FIRST_LOGIN_LABEL)
                .helpText(AspNetIdentityConstants.UPDATE_PROFILE_FIRST_LOGIN_HELP_TEXT)
                .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("true").add().build();
    }
}
