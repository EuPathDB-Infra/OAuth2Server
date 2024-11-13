package org.gusdb.oauth2.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.glassfish.jersey.client.ClientConfig;
import org.gusdb.oauth2.client.KeyStoreTrustManager.KeyStoreConfig;
import org.gusdb.oauth2.client.ValidatedToken.TokenType;
import org.gusdb.oauth2.exception.ConflictException;
import org.gusdb.oauth2.exception.ExpiredTokenException;
import org.gusdb.oauth2.exception.InvalidPropertiesException;
import org.gusdb.oauth2.exception.InvalidTokenException;
import org.gusdb.oauth2.shared.ECPublicKeyRepresentation;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.security.SignatureException;

public class OAuthClient {

  private static final Logger LOG = LogManager.getLogger(OAuthClient.class);

  private static final String NL = System.lineSeparator();

  public static final String JSON_KEY_CREDENTIALS = "clientCredentials";
  public static final String JSON_KEY_CLIENT_ID = "clientId";
  public static final String JSON_KEY_CLIENT_SECRET = "clientSecret";

  public static final String OAUTH_KEY_CLIENT_ID = "client_id";
  public static final String OAUTH_KEY_CLIENT_SECRET = "client_secret";
  public static final String OAUTH_KEY_GRANT_TYPE = "grant_type";

  private static final String AUTHORIZATION_HEADER_VALUE_PREFIX = "Bearer ";

  // applications can configure or turn off public key cache if desired
  public static AtomicBoolean USE_PUBLIC_KEY_CACHE = new AtomicBoolean(true);
  public static AtomicInteger PUBLIC_KEY_CACHE_DURATION_SECS = new AtomicInteger(120); // two minutes

  // values used to store and control cached public signing key
  private static String CACHED_PUBLIC_KEY = null;
  private static String LAST_PUBLIC_KEY_FETCH_URL = null;
  private static long PUBLIC_KEY_FETCH_EXPIRATION = 0;

  public static String getTokenFromAuthHeader(String authHeader) {
    Objects.requireNonNull(authHeader);
    authHeader = authHeader.trim();
    if (!authHeader.toLowerCase().startsWith(AUTHORIZATION_HEADER_VALUE_PREFIX.toLowerCase())) {
      throw new NotAuthorizedException(HttpHeaders.AUTHORIZATION +
          " header must send token of type '" + AUTHORIZATION_HEADER_VALUE_PREFIX.trim() + "'");
    }
    return authHeader.substring(AUTHORIZATION_HEADER_VALUE_PREFIX.length(), authHeader.length());
  }

  public static TrustManager getTrustManager(KeyStoreConfig config) {
    String keyStoreFile = config.getKeyStoreFile();
    return (keyStoreFile.isEmpty() ? new KeyStoreTrustManager() :
        new KeyStoreTrustManager(Paths.get(keyStoreFile), config.getKeyStorePassPhrase()));
  }

  public static SSLContext getSSLContext(KeyStoreConfig config) {
    try {
      return createSslContext(getTrustManager(config));
    }
    catch (KeyManagementException | NoSuchAlgorithmException e) {
      throw new RuntimeException("Unable to create SSL context using trust manager created by key store config pointing to " + config.getKeyStoreFile());
    }
  }

  // manages SSL certs needed to connect to OAuth server (SSL required)
  private final TrustManager _trustManager;

  public OAuthClient(TrustManager trustManager) {
    _trustManager = trustManager;
  }

  private String getPublicSigningKey(String oauthBaseUrl) {
    return USE_PUBLIC_KEY_CACHE.get() ? getCachedPublicSigningKey(oauthBaseUrl) : fetchPublicSigningKey(oauthBaseUrl);
  }

  private synchronized String getCachedPublicSigningKey(String oauthBaseUrl) {
    // cache new value if first fetch, different oauth URL, or current value expired
    if (LAST_PUBLIC_KEY_FETCH_URL == null
        || !LAST_PUBLIC_KEY_FETCH_URL.equals(oauthBaseUrl)
        || System.currentTimeMillis() > PUBLIC_KEY_FETCH_EXPIRATION) {
      LOG.trace("Cached public key expired; refreshing from " + oauthBaseUrl + Endpoints.JWKS);
      CACHED_PUBLIC_KEY = fetchPublicSigningKey(oauthBaseUrl);
      LAST_PUBLIC_KEY_FETCH_URL = oauthBaseUrl;
      PUBLIC_KEY_FETCH_EXPIRATION = System.currentTimeMillis() + (PUBLIC_KEY_CACHE_DURATION_SECS.get() * 1000);
    }
    return CACHED_PUBLIC_KEY;
  }
  
  private String fetchPublicSigningKey(String oauthBaseUrl) {
    String jwksEndpoint = oauthBaseUrl + Endpoints.JWKS;

    // get JWKS response from OAuth server
    try (Response response = ClientBuilder.newBuilder()
          .withConfig(new ClientConfig())
          .sslContext(createSslContext(_trustManager))
          .build()
          .target(jwksEndpoint)
          .request(MediaType.APPLICATION_JSON)
          .get()) {

      // check for successful processing
      if (response.getStatus() != 200) {
        String responseBody = !response.hasEntity() ? "<empty>" : readResponseBody(response);
        throw new RuntimeException("Failure to get JWKS information.  GET " + jwksEndpoint + " returned " + response.getStatus() + " with body: " + responseBody);
      }

      // parse response and find elliptic curve public key
      JSONObject jwksJson = new JSONObject(readResponseBody(response));
      return findECPublicKeyValue(jwksJson);

    }
    catch (KeyManagementException | NoSuchAlgorithmException | JSONException | IOException e) {
      throw new RuntimeException("Unable to retrieve public signing key from OAuth service at " + jwksEndpoint, e);
    }
  }

  private static String findECPublicKeyValue(JSONObject jwksJson) {
    JSONArray keys = jwksJson.getJSONArray("keys");
    for (int i = 0; i < keys.length(); i++) {
      JSONObject keyDef = keys.getJSONObject(i);
      if (keyDef.getString("kty").equals("EC")) {
        // specific to our OAuth implementation; typically EC key returns
        //   x and y coords, which we also do, but this is easier to interpret
        return keyDef.getString("k");
      }
    }
    throw new RuntimeException("Unable to find EC key information in JWKS response: " + jwksJson.toString(2));
  }

  public static String readResponseBody(Response response) throws IOException {
    InputStream entity = (InputStream)response.getEntity();
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    entity.transferTo(body);
    return body.toString(StandardCharsets.UTF_8);
  }

  private interface TokenSupplier {
    ValidatedToken getToken() throws InvalidTokenException, ExpiredTokenException;
  }

  private ValidatedToken hideBadTokenExceptions(TokenSupplier tokenSupplier) throws InvalidPropertiesException {
    try {
      return tokenSupplier.getToken();
    }
    catch (IllegalArgumentException e) {
      throw new InvalidPropertiesException(e.getMessage());
    }
    catch (InvalidTokenException | ExpiredTokenException e) {
      throw new RuntimeException("Unexpected validation failure of 'known' token", e);
    }
  }

  private Consumer<MultivaluedMap<String, String>> getAuthCodeFormModifier(String authCode) {
    return formData -> {
      formData.add(OAUTH_KEY_GRANT_TYPE, "authorization_code");
      formData.add("code", authCode);
    };
  }

  public ValidatedToken getIdTokenFromAuthCode(OAuthConfig oauthConfig, String authCode, String redirectUri) throws InvalidPropertiesException {

    // get legacy token, signed with HMAC using client secret as the key
    String token = getToken(Endpoints.ID_TOKEN, getAuthCodeFormModifier(authCode), oauthConfig, redirectUri);

    // validate signature and return parsed claims
    return hideBadTokenExceptions(() -> getValidatedHmacSignedToken(oauthConfig.getOauthClientSecret(), token));
  }

  public ValidatedToken getBearerTokenFromAuthCode(OAuthConfig oauthConfig, String authCode, String redirectUri) throws InvalidPropertiesException {

    // get bearer token, signed with ECDSA using public/private key pair
    String token = getToken(Endpoints.BEARER_TOKEN, getAuthCodeFormModifier(authCode), oauthConfig, redirectUri);

    // validate signature and return parsed claims
    return hideBadTokenExceptions(() -> getValidatedEcdsaSignedToken(oauthConfig.getOauthUrl(), token));
  }

  private Consumer<MultivaluedMap<String, String>> getUserPassFormModifier(String username, String password) {
    return formData -> {
      formData.add(OAUTH_KEY_GRANT_TYPE, "password");
      formData.add("username", username);
      formData.add("password", password);
    };
  }

  public ValidatedToken getIdTokenFromUsernamePassword(OAuthConfig oauthConfig, String username, String password, String redirectUri) throws InvalidPropertiesException {

    // get legacy token, signed with HMAC using client secret as the key
    String token = getToken(Endpoints.ID_TOKEN, getUserPassFormModifier(username, password), oauthConfig, redirectUri);

    // validate signature and return parsed claims
    return hideBadTokenExceptions(() -> getValidatedHmacSignedToken(oauthConfig.getOauthClientSecret(), token));
  }

  public ValidatedToken getBearerTokenFromUsernamePassword(OAuthConfig oauthConfig, String username, String password, String redirectUri) throws InvalidPropertiesException {

    // get bearer token, signed with ECDSA using public/private key pair
    String token = getToken(Endpoints.BEARER_TOKEN, getUserPassFormModifier(username, password), oauthConfig, redirectUri);

    // validate signature and return parsed claims
    return hideBadTokenExceptions(() -> getValidatedEcdsaSignedToken(oauthConfig.getOauthUrl(), token));
  }

  public ValidatedToken getNewGuestToken(OAuthConfig oauthConfig) {
    try {
      // get guest bearer token, signed with ECDSA using public/private key pair
      String token = getToken(Endpoints.GUEST_TOKEN, form -> {}, oauthConfig, null);

      // validate signature and return parsed claims
      return getValidatedEcdsaSignedToken(oauthConfig.getOauthUrl(), token);
    }
    catch (ExpiredTokenException | InvalidTokenException e) {
      throw new IllegalStateException("New guest token returned from OAuth is not valid!", e);
    }
  }

  private String getToken(String path, Consumer<MultivaluedMap<String, String>> formModifier, OAuthConfig oauthConfig, String redirectUri) {

    String oauthUrl = oauthConfig.getOauthUrl() + path;

    // build form parameters for token request
    MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
    formData.add(OAUTH_KEY_CLIENT_ID, oauthConfig.getOauthClientId());
    formData.add(OAUTH_KEY_CLIENT_SECRET, oauthConfig.getOauthClientSecret());

    if (redirectUri != null)
      formData.add("redirect_uri", redirectUri);

    // add custom form params for this grant type
    formModifier.accept(formData);

    LOG.trace("Building token request with the following URL: " + oauthUrl +
        " and params: " + dumpMultiMap(formData));

    // build request and get token response
    try (Response response = ClientBuilder.newBuilder()
          .withConfig(new ClientConfig())
          .sslContext(createSslContext(_trustManager))
          .build()
          .target(oauthUrl)
          .request(MediaType.APPLICATION_JSON)
          .post(Entity.form(formData))) {
  
      if (response.getStatus() == 200) {
        // Success!  Read result into buffer and convert to JSON
        JSONObject json = new JSONObject(readResponseBody(response));
        LOG.trace("Response received from OAuth server for token request: " + json.toString(2));

        // get id_token from object and decode to user ID
        return json.getString("id_token");
      }
      else if (response.getStatus() == 406) {
        String reasonString = readResponseBody(response).trim();
        Optional<UnacceptableRequestReason> reasonOpt = UnacceptableRequestReason.parse(reasonString);
        Function<UnacceptableRequestReason,RuntimeException> exceptionMapper = reason -> {
          switch(reason) {
            case INVALID_AUTH_CODE:
            case INVALID_USERNAME_PASSWORD:
            case INVALID_REDIRECT_URI:
              // these are user input problems
              return new IllegalArgumentException("Could not produce token: " + reason.getDisplay());
            case INVALID_CLIENT:
            case UNSUPPORTED_GRANT_TYPE:
            case UNSUPPORTED_RESPONSE_TYPE:
            default:
              // these are backend code problems
              return new RuntimeException("Received '" + reason.getDisplay() + "' response from OAuth server.");
          }
        };
        // use message associated with reason type, or raw response if unknown type
        throw reasonOpt.map(exceptionMapper).orElse(new RuntimeException(
            "Received '" + reasonString + "' response from OAuth server."));
      }
      else {
        // Failure; throw exception
        throw new RuntimeException("OAuth2 token request failed with status " +
            response.getStatus() + ": " + response.getStatusInfo().getReasonPhrase() + NL + response.getEntity());
      }
    }
    catch(Exception e) {
      throw new RuntimeException("Unable to complete OAuth token request to fetch user id", e);
    }
  }

  public ValidatedToken getValidatedHmacSignedToken(String clientSecret, String token) throws InvalidTokenException, ExpiredTokenException {

    // encode the key as a base64 string
    byte[] unencodedKey = clientSecret.getBytes(StandardCharsets.UTF_8);
    String encodedKeyStr = Base64.getEncoder().encodeToString(unencodedKey);

    // convert the key back to bytes
    byte[] keyBytes = Base64.getDecoder().decode(encodedKeyStr);

    try {
      // verify signature and create claims object
      Claims claims = Jwts.parserBuilder()
          .setSigningKey(keyBytes)
          .build()
          .parseClaimsJws(token)
          .getBody();
  
      validateClaims(claims);
  
      return ValidatedToken.build(TokenType.ID, token, claims);
    }
    catch (ExpiredJwtException e) {
      throw new ExpiredTokenException(e);
    }
    catch (DecodingException | ClassCastException | UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
      throw new InvalidTokenException(e);
    }
  }

  public ValidatedToken getValidatedEcdsaSignedToken(String oauthBaseUrl, String token) throws InvalidTokenException, ExpiredTokenException {

    String key = getPublicSigningKey(oauthBaseUrl);

    // convert the key string to a public key object
    PublicKey publicKey = new ECPublicKeyRepresentation(key).getPublicKey();

    try {
      // verify signature and create claims object
      Claims claims = Jwts.parserBuilder()
          .setSigningKey(publicKey)
          .build()
          .parseClaimsJws(token)
          .getBody();
  
      validateClaims(claims);
  
      return ValidatedToken.build(TokenType.BEARER, token, claims);
    }
    catch (ExpiredJwtException e) {
      throw new ExpiredTokenException(e);
    }
    catch (DecodingException | ClassCastException | UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
      throw new InvalidTokenException(e);
    }
  }

  private void validateClaims(Claims claims) {
    // TODO: add validation of claims
    //claims.getIssuer()
    //claims.getAudience()
  }

  private static SSLContext createSslContext(TrustManager trustManager) throws NoSuchAlgorithmException, KeyManagementException {
    SSLContext sslContext = SSLContext.getInstance("SSL");
    sslContext.init(null, new TrustManager[]{ trustManager }, null);
    return sslContext;
  }

  private static String dumpMultiMap(MultivaluedMap<String, String> formData) {
    StringBuilder str = new StringBuilder("{").append(NL);
    for (Entry<String,List<String>> entry : formData.entrySet()) {
      String value = entry.getKey().equals("password") || entry.getKey().equals("client_secret") ? "<hidden>" :
        entry.getValue().stream().collect(Collectors.joining(", "));
      str.append("  ").append(entry.getKey()).append(": ")
         .append("[ ").append(value).append(" ]").append(NL);
    }
    return str.append("}").append(NL).toString();
  }

  public static String getAuthorizationHeaderValue(ValidatedToken token) {
    if (token.getTokenType() != TokenType.BEARER) {
      throw new RuntimeException("User info and edit endpoints require a user's bearer token (legacy auth tokens are not supported).");
    }
    return AUTHORIZATION_HEADER_VALUE_PREFIX + token.getTokenValue();
  }

  public JSONObject getUserData(String oauthBaseUrl, ValidatedToken token) {
    String url = oauthBaseUrl + Endpoints.USER_INFO;
    //LOG.info("Will send Authorization header value: " + getAuthorizationHeaderValue(token));
    // build request and get JSON response
    try (Response response = ClientBuilder.newBuilder()
          .withConfig(new ClientConfig())
          .sslContext(createSslContext(_trustManager))
          .build()
          .target(url)
          .request(MediaType.APPLICATION_JSON)
          .header(HttpHeaders.AUTHORIZATION, getAuthorizationHeaderValue(token))
          .get()) {

      if (response.getStatus() == 200) {
        return new JSONObject(readResponseBody(response));
      }

      // otherwise request failed
      throw new RuntimeException("Unable to retrieve user info from OAuth server.  GET " + url + " returned " + response.getStatus());

    }
    catch (Exception e) {
      throw new RuntimeException("Unable to retrieve user info from OAuth server", e);
    }
  }

  public JSONObject createNewUser(OAuthConfig oauthConfig, Map<String,String> userProperties) throws InvalidPropertiesException, ConflictException {
    return new JSONObject(performCredentialsBasedRequest(
        Endpoints.USER_CREATE,
        oauthConfig,
        json -> json.put("user", userProperties),
        (builder,entity) -> builder.post(entity)
    ));
  }

  public JSONObject modifyUser(OAuthConfig oauthConfig, ValidatedToken token, Map<String,String> userProperties) throws InvalidPropertiesException, ConflictException {
    return new JSONObject(performCredentialsBasedRequest(
        Endpoints.USER_EDIT,
        oauthConfig,
        json -> json.put("user",  userProperties),
        (builder,entity) -> builder
          .header(HttpHeaders.AUTHORIZATION, getAuthorizationHeaderValue(token))
          .put(entity)
    ));
  }

  public JSONObject resetPassword(OAuthConfig oauthConfig, String loginName) throws InvalidPropertiesException {
    try {
      return new JSONObject(performCredentialsBasedRequest(
          Endpoints.PASSWORD_RESET,
          oauthConfig,
          json -> json.put("loginName",  loginName),
          (builder,entity) -> builder.post(entity)
      ));
    }
    catch (ConflictException e) {
      // this should never happen; password_reset does not throw 409
      throw new RuntimeException(e);
    }
  }

  public String queryOAuth(OAuthConfig oauthConfig, JSONObject queryConfig) {
    try {
      return performCredentialsBasedRequest(
          Endpoints.QUERY_USERS,
          oauthConfig,
          json -> json
            .put("query", queryConfig),
          (builder,entity) -> builder.post(entity)
      );
    }
    catch (InvalidPropertiesException | ConflictException e) {
      // this should never happen; user query does not throw 422 or 409
      throw new RuntimeException(e);
    }
  }

  private String performCredentialsBasedRequest(String endpointPath, OAuthConfig oauthConfig,
      Function<JSONObject,JSONObject> jsonModifier, BiFunction<Invocation.Builder,Entity<String>,Response> responseSupplier) throws InvalidPropertiesException, ConflictException {

    String endpoint = oauthConfig.getOauthUrl() + endpointPath;

    JSONObject initialJson = new JSONObject()
        .put(JSON_KEY_CREDENTIALS, new JSONObject()
            .put(JSON_KEY_CLIENT_ID, oauthConfig.getOauthClientId())
            .put(JSON_KEY_CLIENT_SECRET, oauthConfig.getOauthClientSecret()));

    String requestJson = jsonModifier.apply(initialJson).toString();

    // build request and get JSON response
    try (Response response = responseSupplier.apply(
        ClientBuilder.newBuilder()
          .withConfig(new ClientConfig())
          .sslContext(createSslContext(_trustManager))
          .build()
          .target(endpoint)
          .request(MediaType.APPLICATION_JSON),
        Entity.entity(requestJson, MediaType.APPLICATION_JSON))) {

      // return new user's user info object
      if (response.getStatus() == 200) {
        return readResponseBody(response);
      }

      // check for input validation issues
      if (response.getStatusInfo().getFamily().equals(Status.Family.CLIENT_ERROR)) {
        if (response.getStatus() == HttpStatus.UNPROCESSABLE_CONTENT.getStatusCode()) {
          throw new InvalidPropertiesException(readResponseBody(response));
        }
        if (response.getStatus() == Status.CONFLICT.getStatusCode()) {
          throw new ConflictException(readResponseBody(response));
        }
        // propagate 401/403 responses, converting back to the associated exceptions
        if (response.getStatus() == Status.UNAUTHORIZED.getStatusCode()) {
          throw new NotAuthorizedException(readResponseBody(response));
        }
        if (response.getStatus() == Status.FORBIDDEN.getStatusCode()) {
          throw new ForbiddenException(readResponseBody(response));
        }
        // a 400 indicates a syntax error (e.g. JSON misformat) on our side and should be a 500
        // a 406 indicates a misconfiguration (client does not have perms for this type of request) and should be a 500
        throw new RuntimeException("Created bad request to " + endpoint + "; returned " + response.getStatus() + ", " + readResponseBody(response));
      }

      // else server error
      throw new RuntimeException("Unable to perform credentialed operation on OAuth server.  " + endpoint + " returned " + response.getStatus());
      
    }
    catch (IOException | KeyManagementException | NoSuchAlgorithmException e) {
      throw new RuntimeException("Unable to perform credentialed operation on OAuth server", e);
    }
  }

}
