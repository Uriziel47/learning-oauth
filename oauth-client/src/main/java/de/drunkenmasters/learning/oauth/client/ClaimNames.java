package de.drunkenmasters.learning.oauth.client;

public enum ClaimNames {
    NAME("name"),
    ;
    private String name;

    ClaimNames(String name) {
        this.name = name;
    }
    public String getName() {
        return name;
    }
}
