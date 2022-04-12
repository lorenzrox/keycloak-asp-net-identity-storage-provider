package org.keycloak.storage.aspnet;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.UserStorageProvider.EditMode;
import org.keycloak.storage.user.ImportSynchronization;
import org.keycloak.storage.user.SynchronizationResult;

public class AspNetIdentityStorageProviderFactory
        implements UserStorageProviderFactory<AspNetIdentityStorageProvider>, ImportSynchronization {
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
        return ProviderConfigurationBuilder.create()
                .property().name(UserStorageProviderModel.IMPORT_ENABLED)
                .label(AspNetIdentityConstants.IMPORT_ENABLED_LABEL)
                .helpText(AspNetIdentityConstants.IMPORT_ENABLED_HELP_TEXT).type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()

                .property().name(AspNetIdentityProviderModel.EDIT_MODE)
                .label(AspNetIdentityConstants.EDIT_MODE_LABEL)
                .helpText(AspNetIdentityConstants.EDIT_MODE_HELP_TEXT)
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(Arrays.stream(EditMode.values())
                        .map(EditMode::name)
                        .collect(Collectors.toList()))
                .defaultValue(EditMode.UNSYNCED.name())
                .add()

                .property().name(AspNetIdentityProviderModel.DB_URL)
                .label(AspNetIdentityConstants.DB_URL_LABEL).helpText(AspNetIdentityConstants.DB_URL_HELP_TEXT)
                .type(ProviderConfigProperty.STRING_TYPE).add()

                .property().name(AspNetIdentityProviderModel.DB_USER).label(AspNetIdentityConstants.DB_USER_LABEL)
                .helpText(AspNetIdentityConstants.DB_USER_HELP_TEXT).type(ProviderConfigProperty.STRING_TYPE).add()

                .property().name(AspNetIdentityProviderModel.DB_PASSWORD)
                .label(AspNetIdentityConstants.DB_PASSWORD_LABEL)
                .helpText(AspNetIdentityConstants.DB_PASSWORD_HELP_TEXT).type(ProviderConfigProperty.PASSWORD).add()

                .property().name(AspNetIdentityProviderModel.APPLICATION_NAME)
                .label(AspNetIdentityConstants.APPLICATION_NAME_LABEL)
                .helpText(AspNetIdentityConstants.APPLICATION_NAME_HELP_TEXT).type(ProviderConfigProperty.STRING_TYPE)
                .add()

                .property().name(AspNetIdentityProviderModel.VALIDATION_ALGORITHM)
                .label(AspNetIdentityConstants.VALIDATION_ALGORITHM_LABEL)
                .helpText(AspNetIdentityConstants.VALIDATION_ALGORITHM_HELP_TEXT).type(ProviderConfigProperty.LIST_TYPE)
                .options(Arrays.stream(AspNetIdentityValidationAlgorithm.values())
                        .map(AspNetIdentityValidationAlgorithm::name)
                        .collect(Collectors.toList()))
                .defaultValue(AspNetIdentityValidationAlgorithm.SHA1.name()).add()

                .property().name(AspNetIdentityProviderModel.ALLOW_PASSWORD_AUTHENTICATION)
                .label(AspNetIdentityConstants.ALLOW_PASSWORD_AUTHENTICATION_LABEL)
                .helpText(AspNetIdentityConstants.ALLOW_PASSWORD_AUTHENTICATION_HELP_TEXT)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()

                .property().name(AspNetIdentityProviderModel.UPDATE_PROFILE_FIRST_LOGIN)
                .label(AspNetIdentityConstants.UPDATE_PROFILE_FIRST_LOGIN_LABEL)
                .helpText(AspNetIdentityConstants.UPDATE_PROFILE_FIRST_LOGIN_HELP_TEXT)
                .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("true").add()

                .property().name(AspNetIdentityProviderModel.UPDATE_PASSWORD_FIRST_LOGIN)
                .label(AspNetIdentityConstants.UPDATE_PASSWORD_FIRST_LOGIN_LABEL)
                .helpText(AspNetIdentityConstants.UPDATE_PASSWORD_FIRST_LOGIN_HELP_TEXT)
                .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("true").add()

                .build();
    }

    @Override
    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId,
            UserStorageProviderModel model) {
        return syncSince(null, sessionFactory, realmId, model);
    }

    @Override
    public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId,
            UserStorageProviderModel model) {
        final SynchronizationResult syncResult = new SynchronizationResult();

        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {
            @Override
            public void run(KeycloakSession session) {
                try {
                    AspNetIdentityStorageProvider provider = (AspNetIdentityStorageProvider) session
                            .getProvider(UserStorageProvider.class, model);

                    RealmModel realm = session.realms().getRealm(realmId);
                    session.getContext().setRealm(realm);

                    syncResult.add(provider.importAllUsers(realm, lastSync));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });

        return syncResult;
    }
}
