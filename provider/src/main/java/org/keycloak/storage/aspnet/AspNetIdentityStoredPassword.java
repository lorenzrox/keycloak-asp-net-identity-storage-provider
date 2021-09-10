package org.keycloak.storage.aspnet;

public class AspNetIdentityStoredPassword {
    private String password;
    private String salt;
    private Integer format;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public Integer getFormat() {
        return format;
    }

    public void setFormat(Integer format) {
        this.format = format;
    }

    @Override
    public String toString() {
        return String.format("password=%s, salt=%s, format=%d", password, salt, format);
    }
}
