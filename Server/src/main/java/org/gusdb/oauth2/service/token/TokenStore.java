package org.gusdb.oauth2.service.token;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Manages state on the OAuth server.  This includes OAuth server sessions,
 * their owners, and associated authentication codes and tokens
 * 
 * @author ryan
 */
public class TokenStore {

  private static final Logger LOG = LogManager.getLogger(TokenStore.class);

  /*
   * HttpSession contains the username (string used in username field of
   * submitted form) of a user if the user has successfully authenticated
   * in the given session.  Any forms sent out before then are either
   * anonymous (accessed directly by client), or identified by an ID as
   * part of an OAuth authentication flow.  The ID is keyed to a set of
   * parameters sent as part of an authentication request and is used to
   * redirect the user to the proper location (with an auth code) once
   * he has successfully authenticated.  Form IDs are retained as part of
   * the session until the form is submitted, or until the session expires
   * or the user logs out.
   */

  public static class IdTokenParams {

    protected final String _clientId;
    protected final String _nonce;
    protected final long _creationTime;

    public IdTokenParams(String clientId, String nonce) {
      _clientId = clientId;
      _nonce = nonce;
      _creationTime = new Date().getTime() / 1000;
    }

    public String getClientId() {
      return _clientId;
    }

    public String getNonce() {
      return _nonce;
    }

    public long getCreationTime() {
      return _creationTime;
    }
  }

  public static class AuthCodeData extends IdTokenParams {

    private final String _authCode;
    private final String _userId;

    public AuthCodeData(String authCode, String clientId, String userId, String nonce) {
      super(clientId, nonce);
      _authCode = authCode;
      _userId = userId;
    }

    @Override
    public String toString() {
      return new StringBuilder()
        .append("{ authCode: ").append(_authCode)
        .append(", clientId: ").append(_clientId)
        .append(", nonce: ").append(_nonce)
        .append(", authTime: ").append(_creationTime)
        .append(" }").toString();
    }

    @Override
    public boolean equals(Object other) {
      return (other instanceof AuthCodeData &&
          _authCode.equals(((AuthCodeData)other)._authCode));
    }

    @Override
    public int hashCode() {
      return _authCode.hashCode();
    }

    public String getAuthCode() {
      return _authCode;
    }

    public String getUserId() {
      return _userId;
    }
  }

  public static class AccessTokenData {

    public final String tokenValue;
    public final AuthCodeData authCodeData;
    public final long creationTime;

    public AccessTokenData(String tokenValue, AuthCodeData authCodeData) {
      this.tokenValue = tokenValue;
      this.authCodeData = authCodeData;
      this.creationTime = new Date().getTime() / 1000;
    }

    @Override
    public boolean equals(Object other) {
      return (other instanceof AccessTokenData &&
          tokenValue.equals(((AccessTokenData)other).tokenValue));
    }

    @Override
    public int hashCode() {
      return tokenValue.hashCode();
    }
  }

  // maps to provide data lookup from code or token value
  private static final Map<String /* key = auth_code */, AuthCodeData> AUTH_CODE_MAP = new HashMap<>();
  private static final Map<String /* key = token     */, AccessTokenData> ACCESS_TOKEN_MAP = new HashMap<>();
  private static final Map<String /* key = user_id   */, List<AuthCodeData>> USER_AUTH_CODE_MAP = new HashMap<>();
  private static final Map<String /* key = user_id   */, List<AccessTokenData>> USER_ACCESS_TOKEN_MAP = new HashMap<>();

  public static synchronized void addAuthCode(AuthCodeData authCodeData) {
    AUTH_CODE_MAP.put(authCodeData.getAuthCode(), authCodeData);
    LOG.debug("Added auth code with data:" + authCodeData);
    List<AuthCodeData> list = USER_AUTH_CODE_MAP.get(authCodeData.getUserId());
    if (list == null) {
      list = new ArrayList<>();
      USER_AUTH_CODE_MAP.put(authCodeData.getUserId(), list);
    }
    list.add(authCodeData);
  }

  public static synchronized AccessTokenData addAccessToken(String accessToken, String authCode) {
    LOG.debug("Adding access token '" + accessToken + "' to user behind auth code '" + authCode + "'.");
    AuthCodeData authCodeData = AUTH_CODE_MAP.get(authCode);
    AccessTokenData accessTokenData = new AccessTokenData(accessToken, authCodeData);
    ACCESS_TOKEN_MAP.put(accessTokenData.tokenValue, accessTokenData);
    List<AccessTokenData> list = USER_ACCESS_TOKEN_MAP.get(accessTokenData.authCodeData.getUserId());
    if (list == null) {
      list = new ArrayList<>();
      USER_ACCESS_TOKEN_MAP.put(accessTokenData.authCodeData.getUserId(), list);
    }
    list.add(accessTokenData);
    return accessTokenData;
  }

  public static synchronized boolean isValidAuthCode(String authCode, String clientId) {
    if (LOG.isDebugEnabled()) LOG.debug(dumpAuthCodeMap());
    return AUTH_CODE_MAP.containsKey(authCode) && AUTH_CODE_MAP.get(authCode).getClientId().equals(clientId);
  }

  private static String dumpAuthCodeMap() {
    String NL = System.lineSeparator();
    StringBuilder str = new StringBuilder("AUTH_CODE_MAP:").append(NL);
    for (Entry<String, AuthCodeData> entry : AUTH_CODE_MAP.entrySet()) {
      str.append(entry.getKey()).append(": ").append(entry.getValue().toString());
    }
    return str.toString();
  }


  public static AccessTokenData getTokenData(String accessToken) {
    return ACCESS_TOKEN_MAP.get(accessToken);
  }

  public static String getUserIdForToken(String accessToken) {
    AccessTokenData data = ACCESS_TOKEN_MAP.get(accessToken);
    if (data != null) {
      return data.authCodeData.getUserId();
    }
    return null;
  }

  public static synchronized void clearObjectsForUser(String userId) {
    List<AuthCodeData> codeList = USER_AUTH_CODE_MAP.remove(userId);
    if (codeList != null)
      for (AuthCodeData data : codeList)
        AUTH_CODE_MAP.remove(data.getAuthCode());
    List<AccessTokenData> tokenList = USER_ACCESS_TOKEN_MAP.remove(userId);
    if (tokenList != null)
      for (AccessTokenData data : tokenList)
        ACCESS_TOKEN_MAP.remove(data.tokenValue);
  }

  public static synchronized void removeExpiredTokens(int expirationSeconds) {
    long currentDateSecs = new Date().getTime() / 1000;
    List<String> expiredCodes = new ArrayList<>();
    for (Entry<String, AuthCodeData> entry : AUTH_CODE_MAP.entrySet()) {
      if (isExpired(entry.getValue().getCreationTime(), currentDateSecs, expirationSeconds)) {
        expiredCodes.add(entry.getKey());
      }
    }
    LOG.debug("Expiring the following auth codes: " + Arrays.toString(expiredCodes.toArray()));
    for (String authCode : expiredCodes) {
      AuthCodeData removedCode = AUTH_CODE_MAP.remove(authCode);
      String userId = removedCode.getUserId();
      USER_AUTH_CODE_MAP.get(userId).remove(removedCode);
      if (USER_AUTH_CODE_MAP.get(userId).isEmpty()) {
        USER_AUTH_CODE_MAP.remove(userId);
      }
    }
    List<String> expiredTokens = new ArrayList<>();
    for (Entry<String, AccessTokenData> entry : ACCESS_TOKEN_MAP.entrySet()) {
      if (isExpired(entry.getValue().creationTime, currentDateSecs, expirationSeconds)) {
        expiredTokens.add(entry.getKey());
      }
    }
    LOG.debug("Expiring the following access tokens: " + Arrays.toString(expiredTokens.toArray()));
    for (String accessToken : expiredTokens) {
      AccessTokenData removedToken = ACCESS_TOKEN_MAP.remove(accessToken);
      String userId = removedToken.authCodeData.getUserId();
      USER_ACCESS_TOKEN_MAP.get(userId).remove(removedToken);
      if (USER_ACCESS_TOKEN_MAP.get(userId).isEmpty()) {
        USER_ACCESS_TOKEN_MAP.remove(userId);
      }
    }
  }

  private static boolean isExpired(long creationTimeSecs, long currentDateSecs, int expirationSeconds) {
    long ageMillis = currentDateSecs - creationTimeSecs;
    return (ageMillis > expirationSeconds);
  }
}
