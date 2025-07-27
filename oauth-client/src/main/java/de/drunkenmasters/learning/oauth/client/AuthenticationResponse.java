package de.drunkenmasters.learning.oauth.client;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.Scope;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthenticationResponse {

    private JWT idToken;
    private JWT accessToken;
    private JWT refreshToken;

    private int refreshExpiresIn;
    private int notBeforePolicy;

    private Scope scope;
    private String sessionState;
    private int expiresIn;
    private String tokenType;
}
