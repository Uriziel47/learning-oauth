package de.drunkenmasters.learning.oauth.client;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.Scope;
import lombok.NoArgsConstructor;
import net.minidev.json.JSONObject;

import java.text.ParseException;

@NoArgsConstructor(staticName = "of")
public class AuthenticationResponseMapper {

    public AuthenticationResponse from(JSONObject jsonObject) throws Exception {
        return AuthenticationResponse.builder()
                .idToken(extractJwt(jsonObject, "id_token"))
                .accessToken(extractJwt(jsonObject, "access_token"))
                .refreshToken(extractJwt(jsonObject, "refresh_token"))
                .refreshExpiresIn(extractInt(jsonObject, "refresh_expires_in"))
                .notBeforePolicy(extractInt(jsonObject, "not-before-policy"))
                .scope(extractScope(jsonObject, "scope"))
                .sessionState(jsonObject.getAsString("session_state"))
                .expiresIn(extractInt(jsonObject, "expires_in"))
                .tokenType(jsonObject.getAsString("token_type"))
                .build();
    }

    private JWT extractJwt(JSONObject jsonObject, String key) throws ParseException {
        var value = jsonObject.getAsString(key);
        return JWTParser.parse(value);
    }

    private int extractInt(JSONObject jsonObject, String key) {
        var value = jsonObject.getAsNumber(key);
        return value.intValue();
    }

    private Scope extractScope(JSONObject jsonObject, String key) {
        var value = jsonObject.getAsString(key);
        return Scope.parse(value);
    }
}
