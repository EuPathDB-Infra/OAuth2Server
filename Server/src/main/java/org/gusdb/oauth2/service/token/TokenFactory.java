package org.gusdb.oauth2.service.token;

import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.ws.rs.ForbiddenException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.gusdb.oauth2.Authenticator;
import org.gusdb.oauth2.Authenticator.DataScope;
import org.gusdb.oauth2.UserAccountInfo;
import org.gusdb.oauth2.service.token.TokenStore.IdTokenParams;
import org.gusdb.oauth2.shared.IdTokenFields;

public class TokenFactory {

  private static final Logger LOG = LogManager.getLogger(TokenFactory.class);

  public static JsonObject createTokenJson(Authenticator authenticator, String userId,
      IdTokenParams tokenParams, String issuer, int expirationSecs, DataScope scope)
          throws OAuthSystemException {
    assert(scope != DataScope.PROFILE);

    // get values from authenticator and use to populate fields
    UserAccountInfo user = getUserInfoForToken(authenticator, userId, scope);

    // get base object (common to ID and guest tokens, and user profiles)
    JsonObjectBuilder json = getBaseJson(user);
    appendOidcFields(json, tokenParams, issuer, expirationSecs);
    appendProfileFields(json, user, scope);
    return json.build();
  }

  public static JsonObjectBuilder getBaseJson(UserAccountInfo user) {
    return Json.createObjectBuilder()
      .add(IdTokenFields.sub.name(), user.getUserId())
      .add(IdTokenFields.is_guest.name(), user.isGuest());
  }

  public static JsonObjectBuilder appendProfileFields(JsonObjectBuilder jsonBuilder, UserAccountInfo user, DataScope scope) {
    // add user's email if returned by Authenticator
    String email = user.getEmail();
    if (scope != DataScope.BEARER_TOKEN && email != null && !email.isBlank()) {
      jsonBuilder
        .add(IdTokenFields.email.name(), email)
        .add(IdTokenFields.email_verified.name(), user.isEmailVerified());
    }

    // add user's preferred_username if returned by Authenticator
    String preferredUsername = user.getPreferredUsername();
    if (preferredUsername != null && !preferredUsername.isBlank()) {
      jsonBuilder
        .add(IdTokenFields.preferred_username.name(), preferredUsername);
    }

    // add user signature if returned by Authenticator
    String signature = user.getSignature();
    if (signature != null && !signature.isBlank()) {
      jsonBuilder
        .add(IdTokenFields.signature.name(), signature);
    }

    // add any supplemental fields from Authenticator
    Map<String, JsonValue> extra = user.getSupplementalFields();
    Set<String> reservedKeys = IdTokenFields.getNames();
    for (Entry<String,JsonValue> entry : extra.entrySet()) {
      if (reservedKeys.contains(entry.getKey())) {
        LOG.warn("Authenticator tried to override ID token property [" + entry.getKey() + "]. Skipping...");
      }
      else {
        jsonBuilder.add(entry.getKey(), entry.getValue());
      }
    }

    return jsonBuilder;
  }

  private static JsonObjectBuilder appendOidcFields(JsonObjectBuilder jsonBuilder, IdTokenParams params, String issuer, int expirationSecs) {
    // OpenID Connect claims that we support
    long now = System.currentTimeMillis() / 1000;
    jsonBuilder
      .add(IdTokenFields.iss.name(), issuer)
      .add(IdTokenFields.aud.name(), params.getClientId())
      .add(IdTokenFields.azp.name(), params.getClientId())
      .add(IdTokenFields.auth_time.name(), params.getCreationTime())
      .add(IdTokenFields.iat.name(), now)
      .add(IdTokenFields.exp.name(), now + expirationSecs);

    // add nonce if client sent as part of original authentication request
    String nonce = params.getNonce();
    if (nonce != null && !nonce.isEmpty()) {
      jsonBuilder.add(IdTokenFields.nonce.name(), nonce);
    }
    return jsonBuilder;
  }


  public static JsonObjectBuilder appendPassword(JsonObjectBuilder jsonBuilder, String password) {
    jsonBuilder.add(IdTokenFields.password.name(), password);
    return jsonBuilder;
  }

  public static JsonObject createGuestTokenJson(Authenticator authenticator, String clientId, String issuer, int expirationSecs)
      throws OAuthProblemException {

    if (!authenticator.supportsGuests()) {
      throw OAuthProblemException.error("This token service does not support guest tokens.");
    }

    // get base object (common to ID and guest tokens, and user profiles)
    String guestUserId = authenticator.getNextGuestId();
    UserAccountInfo guestUser = authenticator.getGuestProfileInfo(guestUserId).orElseThrow(); // just inserted on the last line
    JsonObjectBuilder json = getBaseJson(guestUser);
    appendOidcFields(json, new IdTokenParams(clientId, null), issuer, expirationSecs);
    return json.build();
  }

  private static UserAccountInfo getUserInfoForToken(Authenticator authenticator, String userId, DataScope scope) throws OAuthSystemException {
    try {
      return authenticator.getUserInfoByUserId(userId, scope).orElseThrow(() -> {
        LOG.warn("Request made to get user token for user ID '" + userId + "', which does not seem to exist.");
        return new ForbiddenException();
      });
    }
    catch (Exception e) {
      LOG.error("Unable to retrieve user info for user ID '" + userId + "'", e);
      throw new OAuthSystemException(e);
    }
  }

}
