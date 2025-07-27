package de.drunkenmasters.learning.oauth.client;

public enum ClaimNames {
    NAME("name"),
    ACCESS_TOKEN("access_token"),
    REFRESH_TOKEn("refresh_token"),
    ;
    private String name;

    ClaimNames(String name) {
        this.name = name;
    }
    public String getName() {
        return name;
    }
}
