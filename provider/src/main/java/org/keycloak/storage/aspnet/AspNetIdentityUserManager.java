package org.keycloak.storage.aspnet;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.models.UserModel;

public class AspNetIdentityUserManager {
    private final Map<String, ManagedUserEntry> managedUsers = new HashMap<>();

    public UserModel getManagedProxiedUser(String userId) {
        ManagedUserEntry entry = managedUsers.get(userId);
        return entry == null ? null : entry.getManagedProxiedUser();
    }

    public AspNetIdentityUser getManagedAspNetUser(String userId) {
        ManagedUserEntry entry = managedUsers.get(userId);
        return entry == null ? null : entry.getAspNetUser();
    }

    public void setManagedProxiedUser(UserModel proxiedUser, AspNetIdentityUser aspNetUser) {
        String userId = proxiedUser.getId();
        ManagedUserEntry entry = managedUsers.get(userId);
        if (entry != null) {
            throw new IllegalStateException("Don't expect to have entry for user " + userId);
        }

        managedUsers.put(userId, new ManagedUserEntry(proxiedUser, aspNetUser));
    }

    public void removeManagedUserEntry(String userId) {
        managedUsers.remove(userId);
    }

    private static class ManagedUserEntry {
        private final UserModel managedProxiedUser;
        private final AspNetIdentityUser aspNetUser;

        public ManagedUserEntry(UserModel managedProxiedUser, AspNetIdentityUser aspNetUser) {
            this.managedProxiedUser = managedProxiedUser;
            this.aspNetUser = aspNetUser;
        }

        public UserModel getManagedProxiedUser() {
            return managedProxiedUser;
        }

        public AspNetIdentityUser getAspNetUser() {
            return aspNetUser;
        }
    }
}
