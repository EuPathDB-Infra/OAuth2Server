package org.gusdb.oauth2.service;

import java.io.StringReader;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.stream.JsonGenerator;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.as.response.OAuthASResponse.OAuthTokenResponseBuilder;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.rs.request.OAuthAccessResourceRequest;
import org.apache.oltu.oauth2.rs.response.OAuthRSResponse;
import org.gusdb.oauth2.Authenticator;
import org.gusdb.oauth2.Authenticator.DataScope;
import org.gusdb.oauth2.UserInfo;
import org.gusdb.oauth2.config.ApplicationConfig;
import org.gusdb.oauth2.service.token.TokenFactory;
import org.gusdb.oauth2.service.token.TokenStore;
import org.gusdb.oauth2.service.token.TokenStore.AccessTokenData;
import org.gusdb.oauth2.service.token.TokenStore.AuthCodeData;
import org.gusdb.oauth2.service.util.AuthzRequest;
import org.gusdb.oauth2.service.util.StateParamHttpRequest;
import org.gusdb.oauth2.shared.Signatures;
import org.gusdb.oauth2.shared.Signatures.TokenSigner;

public class OAuthRequestHandler {

  private static final Logger LOG = LogManager.getLogger(OAuthRequestHandler.class);

  public static Response handleAuthorizationRequest(AuthzRequest oauthRequest, String loginName, String userId, int expirationSecs)
      throws URISyntaxException, OAuthSystemException {
    OAuthIssuerImpl oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());

    // 'code' is the only response type supported
    String responseType = oauthRequest.getResponseType();
    if (!responseType.equals(ResponseType.CODE.toString())) {
      return new OAuthResponseFactory().buildBadResponseTypeResponse();
    }

    LOG.trace("Cached request values: " + responseType + ", " + oauthRequest.getClientId() + ", " +
        oauthRequest.getRedirectUri() + ", " + oauthRequest.getResponseType());

    LOG.debug("Creating authorization response");
    OAuthASResponse.OAuthAuthorizationResponseBuilder builder = OAuthASResponse.authorizationResponse(
        new StateParamHttpRequest(oauthRequest.getState()), HttpServletResponse.SC_FOUND);

    LOG.debug("Generating authorization code...");
    final String authorizationCode = oauthIssuerImpl.authorizationCode();
    TokenStore.addAuthCode(new AuthCodeData(authorizationCode,
        oauthRequest.getClientId(), loginName, userId, oauthRequest.getNonce()));
    builder.setCode(authorizationCode);

    String redirectURI = oauthRequest.getRedirectUri();
    final OAuthResponse response = builder.location(redirectURI)
        .setExpiresIn(String.valueOf(expirationSecs)).buildQueryMessage();
    URI url = new URI(response.getLocationUri());
    return Response.status(response.getResponseStatus()).location(url).build();
  }

  public static Response handleTokenRequest(OAuthTokenRequest oauthRequest,
      ClientValidator clientValidator, Authenticator authenticator,
      ApplicationConfig config, TokenSigner tokenSigner, DataScope scope, int expirationSecs) throws OAuthSystemException {
    try {
      OAuthResponseFactory responses = new OAuthResponseFactory();
      OAuthIssuer oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());
      // do checking for different grant types
      GrantType grantType = getGrantType(oauthRequest);
      String authCode;
      switch (grantType) {
        case AUTHORIZATION_CODE:
          if (!TokenStore.isValidAuthCode(oauthRequest.getCode(), oauthRequest.getClientId())) {
            LOG.info("Returning bad auth code response; could not find code " +
                oauthRequest.getCode() + " for client " + oauthRequest.getClientId());
            return responses.buildBadAuthCodeResponse();
          }
          authCode = oauthRequest.getCode();
          break;
        case PASSWORD:
          // for ROPC requests, client must be given special permission
          if (!clientValidator.isValidROPCGrantClient(oauthRequest.getClientId(), oauthRequest.getClientSecret())) {
            return new OAuthResponseFactory().buildInvalidClientResponse();
          }
          try {
            Optional<String> userId = authenticator.isCredentialsValid(oauthRequest.getUsername(), oauthRequest.getPassword());
            if (userId.isEmpty()) {
              return new OAuthResponseFactory().buildInvalidUserPassResponse();
            }

            // valid credentials; stub an auth code to store the generated token
            authCode = oauthIssuerImpl.authorizationCode();
            TokenStore.addAuthCode(new AuthCodeData(authCode, oauthRequest.getClientId(), oauthRequest.getUsername(), userId.get(), null));
          }
          catch (Exception e) {
            LOG.error("Could not perform token request.", e);
            return new OAuthResponseFactory().buildServerErrorResponse();
          }
          break;
        case REFRESH_TOKEN:
          // refresh token is not supported in this implementation
          return responses.buildInvalidGrantTypeResponse();
        default:
          return responses.buildInvalidGrantTypeResponse();
      }

      final String accessToken = oauthIssuerImpl.accessToken();
      AccessTokenData tokenData = TokenStore.addAccessToken(accessToken, authCode);

      // tell the authenticator to update the user's last login timestamp if supported
      authenticator.updateLastLoginTimestamp(tokenData.authCodeData.getUserId());

      OAuthTokenResponseBuilder responseBuilder =
          OAuthASResponse.tokenResponse(HttpServletResponse.SC_OK)
          .setTokenType("Bearer")
          .setAccessToken(accessToken)
          .setExpiresIn(String.valueOf(expirationSecs));

      // always send id_token with access token response, create and add it
      JsonObject tokenJson = TokenFactory.createTokenJson(authenticator, tokenData.authCodeData.getLoginName(),
          tokenData.authCodeData, config.getIssuer(), expirationSecs, scope);

      String signedToken = tokenSigner.getSignedEncodedToken(tokenJson, config,
          tokenData.authCodeData.getClientId(), oauthRequest.getClientSecret()); // sign with the same secret sent in

      responseBuilder.setParam("id_token", signedToken);

      OAuthResponse response = responseBuilder.buildJSONMessage();

      if (LOG.isDebugEnabled()) {
        LOG.debug("Processed token request successfully.  Returning: " + prettyPrintJsonObject(response.getBody()));
      }

      return Response.status(response.getResponseStatus()).entity(response.getBody()).build();

    }
    catch (OAuthProblemException e) {
      LOG.error("Problem responding to token request", e);
      OAuthResponse res = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST).error(e).buildJSONMessage();
      return Response.status(res.getResponseStatus()).entity(res.getBody()).build();
    }
  }

  private static GrantType getGrantType(OAuthTokenRequest oauthRequest) throws OAuthProblemException {
    String grantTypeStr = oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE);
    try {
      return GrantType.valueOf(grantTypeStr.toUpperCase());
    }
    catch (IllegalArgumentException e) {
      throw OAuthProblemException.error(OAuthError.TokenResponse.INVALID_REQUEST, "Illegal grant type: " + grantTypeStr);
    }
  }

  public static Response handleUserInfoRequest(OAuthAccessResourceRequest oauthRequest,
      Authenticator authenticator, String issuer, int expirationSecs)
          throws OAuthSystemException {
    String accessToken = oauthRequest.getAccessToken();
    AccessTokenData tokenData = TokenStore.getTokenData(accessToken);

    // Validate the access token
    if (tokenData == null) {
      // create the OAuth error message
      OAuthResponse oauthResponse = OAuthRSResponse
          .errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
          .setError(OAuthError.ResourceResponse.INVALID_TOKEN)
          .buildHeaderMessage();
      // convert to jax-rs response
      String authenticateHeaderValue = oauthResponse.getHeader(OAuth.HeaderType.WWW_AUTHENTICATE);
      return Response
          .status(Response.Status.UNAUTHORIZED)
          .header(OAuth.HeaderType.WWW_AUTHENTICATE, authenticateHeaderValue)
          .build();
    }

    return handleUserInfoRequest(authenticator, tokenData.authCodeData.getUserId(), false);
  }

  public static Response handleUserInfoRequest(Authenticator authenticator, String userId, boolean isGuest) {
    try {
      Optional<UserInfo> user = isGuest
        // treat user ID as guest ID
        ? authenticator.getGuestProfileInfo(userId)
        : authenticator.getUserInfoByUserId(userId, DataScope.PROFILE);
      if (user.isPresent()) {
        return Response
            .status(Response.Status.OK)
            .entity(getUserInfoResponseString(user.get(), Optional.empty()))
            .build();
      }
      else {
        LOG.warn("Request made to get user info for user ID " + userId + ", which does not seem to exist. Throwing 400.");
        throw new BadRequestException();
      }
    }
    catch (Exception e) {
      throw new RuntimeException("Unable to look up user profile information for user ID " + userId + " (isGuest=" + isGuest + ")", e);
    }
  }

  public static JsonObjectBuilder getUserInfoResponseJson(UserInfo user, Optional<String> password) {
    JsonObjectBuilder json = TokenFactory.getBaseJson(user);
    TokenFactory.appendProfileFields(json, user, DataScope.PROFILE);
    password.ifPresent(pw -> TokenFactory.appendPassword(json, pw));
    return json;
  }

  public static String getUserInfoResponseString(UserInfo user, Optional<String> password) {
    return getUserInfoResponseJson(user, password).build().toString();
  }

  public static String prettyPrintJsonObject(String json) {
    JsonObject obj = Json.createReader(new StringReader(json)).readObject();
    StringWriter stringWriter = new StringWriter();
    Map<String, Object> properties = new HashMap<String, Object>(1);
    properties.put(JsonGenerator.PRETTY_PRINTING, true);
    Json.createWriterFactory(properties).createWriter(stringWriter).writeObject(obj);
    return stringWriter.toString();
  }

  public static Response handleGuestTokenRequest(String clientId, Authenticator authenticator, ApplicationConfig config)
      throws OAuthSystemException, OAuthProblemException {

    OAuthIssuer oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());
    final String accessToken = oauthIssuerImpl.accessToken();

    int expirationSecs = config.getBearerTokenExpirationSecs();

    OAuthTokenResponseBuilder responseBuilder =
        OAuthASResponse.tokenResponse(HttpServletResponse.SC_OK)
        .setTokenType("Bearer")
        .setAccessToken(accessToken)
        .setExpiresIn(String.valueOf(expirationSecs));

    JsonObject tokenJson = TokenFactory.createGuestTokenJson(authenticator, clientId, config.getIssuer(), expirationSecs);
    String signedToken = Signatures.ASYMMETRIC_KEY_SIGNER.getSignedEncodedToken(tokenJson, config, clientId, null);

    responseBuilder.setParam("id_token", signedToken);

    OAuthResponse response = responseBuilder.buildJSONMessage();

    if (LOG.isDebugEnabled()) {
      LOG.debug("Processed token request successfully.  Returning: " + prettyPrintJsonObject(response.getBody()));
    }

    return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
  }
}
