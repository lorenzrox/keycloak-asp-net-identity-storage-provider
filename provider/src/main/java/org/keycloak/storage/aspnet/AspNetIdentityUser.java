package org.keycloak.storage.aspnet;

import java.time.Instant;

public class AspNetIdentityUser {
    private String id;
    private String userName;
    private String email;
    private String comment;
    private Boolean isApproved;
    private Boolean isLockedOut;
    private Long createdTimestamp;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Boolean getIsApproved() {
        return isApproved;
    }

    public void setIsApproved(Boolean isApproved) {
        this.isApproved = isApproved;
    }

    public Boolean getIsLockedOut() {
        return isLockedOut;
    }

    public void setIsLockedOut(Boolean isLockedOut) {
        this.isLockedOut = isLockedOut;
    }

    public Long getCreatedTimestamp() {
        return createdTimestamp;
    }

    public void setCreatedTimestamp(Long timestamp) {
        this.createdTimestamp = timestamp;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (!(obj instanceof AspNetIdentityUser)) {
            return false;
        }

        AspNetIdentityUser other = (AspNetIdentityUser) obj;
        return getId() != null && other.getId() != null && getId().equals(other.getId());
    }

    @Override
    public String toString() {
        return String.format(
                "id=%s, userName=%s, email=%s, comment=%s, isApproved=%b, isLockedOut=%b, createdTimeStamp=%s", id,
                userName, email, comment, isApproved, isLockedOut, Instant.ofEpochMilli(createdTimestamp));
    }
}