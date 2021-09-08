package org.keycloak.storage.aspnet;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;

public class AspNetIdentityStorageProviderFactory implements UserStorageProviderFactory<AspNetIdentityStorageProvider> {
    private static final Logger logger = Logger.getLogger(AspNetIdentityStorageProviderFactory.class);
    private static final List<ProviderConfigProperty> configProperties;
    public static final String PROVIDER_NAME = "aspnet-identity";

    static {
        configProperties = getConfigProps();
    }

    @Override
    public AspNetIdentityStorageProvider create(KeycloakSession session, ComponentModel model) {
        return new AspNetIdentityStorageProvider(session, new UserStorageProviderModel(model));
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
        return ProviderConfigurationBuilder.create().build();
    }
}
