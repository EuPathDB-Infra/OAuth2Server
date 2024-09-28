package org.gusdb.oauth2.service;

import static org.gusdb.oauth2.assets.StaticResource.RESOURCE_PREFIX;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.Key;
import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonValue;
import javax.json.stream.JsonParsingException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.core.Variant;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.ParameterStyle;
import org.apache.oltu.oauth2.rs.request.OAuthAccessResourceRequest;
import org.gusdb.oauth2.Authenticator;
import org.gusdb.oauth2.Authenticator.DataScope;
import org.gusdb.oauth2.Authenticator.RequestingUser;
import org.gusdb.oauth2.UserInfo;
import org.gusdb.oauth2.assets.StaticResource;
import org.gusdb.oauth2.client.Endpoints;
import org.gusdb.oauth2.client.HttpStatus;
import org.gusdb.oauth2.client.OAuthClient;
import org.gusdb.oauth2.config.ApplicationConfig;
import org.gusdb.oauth2.exception.ConflictException;
import org.gusdb.oauth2.exception.InvalidPropertiesException;
import org.gusdb.oauth2.server.OAuthServlet;
import org.gusdb.oauth2.service.util.AuthzRequest;
import org.gusdb.oauth2.service.util.JerseyHttpRequestWrapper;
import org.gusdb.oauth2.shared.IdTokenFields;
import org.gusdb.oauth2.shared.Signatures;
import org.gusdb.oauth2.shared.Signatures.TokenSigner;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

@Path("/")
public class OAuthService {

  private static final Logger LOG = LogManager.getLogger(OAuthService.class);

  private static final String FORM_ID_PARAM_NAME = "form_id";

  private static enum LoginFormStatus { failed, error, accessdenied; }

  @Context
  private ServletContext _context;

  @Context
  private HttpServletRequest _request;

  @Context
  private HttpHeaders _headers;

  @Context
  private UriInfo _uriInfo;

  @GET
  @Path(Endpoints.ASSETS + "{name:.+}")
  public Response getStaticFile(@PathParam("name") String name) {
    LOG.trace("Request made to fetch resource: " + name);
    if (name == null || name.isEmpty()) {
      return Response.notAcceptable(Collections.<Variant>emptyList()).build();
    }
    StaticResource resource = new StaticResource(name);
    return resource.getStreamingOutput()
        .map(stream -> Response.ok(stream).type(resource.getMimeType()).build())
        .orElse(Response.status(Status.NOT_FOUND).build());
  }

  @POST
  @Path(Endpoints.LOGIN)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  public Response attemptLogin(
      @FormParam("username") final String loginName,
      @FormParam("password") final String password,
      @HeaderParam("Referer") final String referrer) throws URISyntaxException {
    Session session = new Session(_request.getSession());
    ApplicationConfig config = OAuthServlet.getApplicationConfig(_context);
    String formId = getFormIdFromReferrer(referrer);
    try {
      if ((formId == null || !session.isFormId(formId)) && !config.anonymousLoginsAllowed()) {
        LOG.warn("Attempt to access resources with form ID " + formId +
            " that does not match formId in session (any of " + concat(session.getFormIds()));
        return Response.seeOther(getLoginUri(formId, "", LoginFormStatus.accessdenied)).build();
      }
      Authenticator authenticator = OAuthServlet.getAuthenticator(_context);
      Optional<String> validUserId = authenticator.isCredentialsValid(loginName, password);
      if (validUserId.isPresent()) {
        LOG.info("Authentication successful.  Setting session loginName to " + loginName);

        // add username and userId to session to save a lookup later if /auth endpoint is hit with a known client session
        session.setLoginName(loginName);
        session.setUserId(validUserId.get());

        AuthzRequest originalRequest = (formId == null ? null : session.clearFormId(formId));
        if (originalRequest == null) {
          // formId doesn't exist on this session; give user generic success page
          String baseUri = _uriInfo.getBaseUri().toString().replace("http://", "https://");
          return Response.seeOther(new URI(baseUri + RESOURCE_PREFIX + config.getLoginSuccessPage())).build();
        }
        authenticator.logSuccessfulLogin(loginName, validUserId.get(), originalRequest.getClientId(), originalRequest.getRedirectUri(), _request.getRemoteAddr());
        return OAuthRequestHandler.handleAuthorizationRequest(originalRequest, loginName, validUserId.get(), config.getTokenExpirationSecs());
      }
      else {
        return Response.seeOther(getLoginUri(formId,
            session.getOriginalRequest(formId).getRedirectUri(),
            LoginFormStatus.failed)).build();
      }
    }
    catch (Exception e) {
      LOG.error("Error processing /login request", e);
      return Response.seeOther(getLoginUri(formId, "", LoginFormStatus.error)).build();
    }
  }

  private String concat(Set<String> strs) {
    StringBuilder sb = new StringBuilder("[ ");
    for (String s : strs) { sb.append(s).append(", "); }
    return sb.append("<END>").toString().replace(", <END>", " ]");
  }

  // FIXME: this could probably be done much better with a regex; fix later
  private String getFormIdFromReferrer(String referrer) {
    String formIdPrefix = FORM_ID_PARAM_NAME + "=";
    if (referrer == null) return null;
    int beginIndex = referrer.indexOf(formIdPrefix);
    if (beginIndex == -1) return null;
    referrer = referrer.substring(beginIndex + formIdPrefix.length());
    if (referrer.isEmpty() || referrer.charAt(0) == '&') return null;
    int endIndex = referrer.indexOf("&");
    if (endIndex == -1) return referrer;
    return referrer.substring(0, endIndex);
  }

  @GET
  @Path(Endpoints.LOGOUT)
  public Response logOut(@QueryParam("redirect_uri") String redirectUri) {
    // FIXME: cannot get CORS requests to work so logout can be async from a different domain
    // determine whether this request came from a valid page
    try {
      @SuppressWarnings("unused")
      URL url = new URL(redirectUri);
      //String passedPort = (url.getPort() == -1 ? "" : ":" + url.getPort());
      //String originVal = url.getProtocol() + "://" + url.getHost() + passedPort;
      //ClientValidator clientValidator = OAuthServlet.getClientValidator(_context);
      //if (!clientValidator.isValidLogoutClient(redirectUri)) {
      //  return Response
      //      .status(Status.FORBIDDEN)
      //      .header("Access-Control-Allow-Origin", originVal)
      //      .entity("Valid client redirect URI required")
      //      .build();
      //}

      // invalidate the session
      new Session(_request.getSession()).invalidate();

      // attempt to construct redirect response; if unable, just return 200
      return Response
          .seeOther(new URI(redirectUri))
          //.header("Access-Control-Allow-Origin", originVal)
          .build();
    }
    catch (MalformedURLException | URISyntaxException e) {
      //return new OAuthResponseFactory().buildBadRedirectUrlResponse();
      return Response.ok("Logged out at " + new Date()).build();
    }
  }

  @GET
  @Path(Endpoints.AUTHORIZE)
  public Response authorize() throws URISyntaxException, OAuthSystemException {
    try {
     LOG.info("Handling authorize request with the following params:" +
         System.lineSeparator() + paramsToString(_request));
      OAuthAuthzRequest oauthRequest = new OAuthAuthzRequest(_request);
      ClientValidator clientValidator = OAuthServlet.getClientValidator(_context);
      if (!clientValidator.isValidAuthorizationClient(oauthRequest)) {
        return new OAuthResponseFactory().buildInvalidClientResponse();
      }
      Session session = new Session(_request.getSession());
      if (session.isAuthenticated()) {
        // user is already logged in; respond with auth code for user
        ApplicationConfig config = OAuthServlet.getApplicationConfig(_context);
        return OAuthRequestHandler.handleAuthorizationRequest(new AuthzRequest(oauthRequest),
            session.getLoginName(), session.getUserId(), config.getTokenExpirationSecs());
      }
      else {
        // no one is logged in; generate form ID and send
        AuthzRequest request = new AuthzRequest(oauthRequest);
        return Response.seeOther(getLoginUri(
            session.generateFormId(request),
            request.getRedirectUri(),
            null)).build();
      }
    }
    catch (OAuthProblemException e) {
      LOG.error("Problem with authorize request: ", e);
      return new OAuthResponseFactory().buildInvalidRequestResponse(e);
    }
  }

  private URI getLoginUri(String formId, String redirectUri, LoginFormStatus status) throws URISyntaxException {
    String queryString = "";
    if (formId != null) {
      queryString = FORM_ID_PARAM_NAME + "=" + formId;
    }
    if (redirectUri != null) {
      queryString += (queryString.isEmpty() ? "" : "&") + "redirectUri=" + encodeUrl(redirectUri);
    }
    if (status != null) {
      queryString += (queryString.isEmpty() ? "" : "&") + "status=" + status.name();
    }
    String baseUri = _uriInfo.getBaseUri().toString().replace("http://", "https://");
    return new URI(baseUri + RESOURCE_PREFIX + OAuthServlet.getApplicationConfig(_context).getLoginFormPage() +
        (queryString.isEmpty() ? "" : "?" + queryString));
  }

  private static String encodeUrl(String redirectUri) {
    try {
      return URLEncoder.encode(redirectUri, "UTF-8");
    }
    catch (UnsupportedEncodingException e) {
      throw new RuntimeException("UTF-8 encoding is no longer supported.", e);
    }
  }

  @POST
  @Path(Endpoints.ID_TOKEN)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  public Response getToken(MultivaluedMap<String, String> formParams) throws OAuthSystemException {
    return getOidcTokenResponse(formParams, Signatures.SECRET_KEY_SIGNER, DataScope.ID_TOKEN, config -> config.getTokenExpirationSecs());
  }

  @POST
  @Path(Endpoints.BEARER_TOKEN)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  public Response getBearerToken(MultivaluedMap<String, String> formParams) throws OAuthSystemException {
    return getOidcTokenResponse(formParams, Signatures.ASYMMETRIC_KEY_SIGNER, DataScope.BEARER_TOKEN, config -> config.getBearerTokenExpirationSecs());
  }

  private Response getOidcTokenResponse(
      MultivaluedMap<String,String> formParams,
      TokenSigner signingStrategy,
      DataScope scope,
      Function<ApplicationConfig,Integer> expirationLookup) throws OAuthSystemException {
    try {
      // for POST + URL-encoded form, must use custom HttpServletRequest with Jersey to read actual params
      HttpServletRequest request = new JerseyHttpRequestWrapper(_request, formParams);
      LOG.info("Handling token request with the following params:" +
        System.lineSeparator() + paramsToString(request));
      OAuthTokenRequest oauthRequest = new OAuthTokenRequest(request);
      ClientValidator clientValidator = OAuthServlet.getClientValidator(_context);

      // client needs to be valid for all request types
      if (!clientValidator.isValidTokenClient(oauthRequest)) {
        return new OAuthResponseFactory().buildInvalidClientResponse();
      }

      ApplicationConfig config = OAuthServlet.getApplicationConfig(_context);

      return OAuthRequestHandler.handleTokenRequest(oauthRequest, clientValidator,
          OAuthServlet.getAuthenticator(_context), config, signingStrategy, scope, expirationLookup.apply(config));
    }
    catch (OAuthProblemException e) {
      LOG.error("Problem with authorize request: ", e);
      return new OAuthResponseFactory().buildInvalidRequestResponse(e);
    }
  }

  @POST
  @Path(Endpoints.GUEST_TOKEN)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  public Response getGuestToken(MultivaluedMap<String, String> formParams) throws OAuthSystemException {
    try {
      // for POST + URL-encoded form, must use custom HttpServletRequest with Jersey to read actual params
      HttpServletRequest request = new JerseyHttpRequestWrapper(_request, formParams);

      LOG.info("Handling guest token request with the following params:" +
        System.lineSeparator() + paramsToString(request));

      ClientValidator clientValidator = OAuthServlet.getClientValidator(_context);
      String clientId = request.getParameter(OAuth.OAUTH_CLIENT_ID);
      String clientSecret = request.getParameter(OAuth.OAUTH_CLIENT_SECRET);
      if (!clientValidator.isValidGuestTokenClient(clientId, clientSecret)) {
        return new OAuthResponseFactory().buildInvalidClientResponse();
      }

      return OAuthRequestHandler.handleGuestTokenRequest(
          clientId,
          OAuthServlet.getAuthenticator(_context),
          OAuthServlet.getApplicationConfig(_context));
    }
    catch (OAuthProblemException e) {
      LOG.error("Problem with authorize request: ", e);
      return new OAuthResponseFactory().buildInvalidRequestResponse(e);
    }
  }

  private static String paramsToString(HttpServletRequest request) {
    Map<String, String[]> params = request.getParameterMap();
    StringBuilder sb = new StringBuilder("{").append(System.lineSeparator());
    for (String key : params.keySet()) {
      String[] values = (key.equals("client_secret") ? new String[]{ "<blocked>" } : params.get(key));
      sb.append("  ").append(key).append(": ")
        .append(Arrays.toString(values)).append(System.lineSeparator());
    }
    return sb.append("}").toString();
  }

  @GET
  @Path(Endpoints.USER_INFO)
  @Produces(MediaType.APPLICATION_JSON)
  public Response getAccount() throws OAuthSystemException {

    String authHeader = _request.getHeader(HttpHeaders.AUTHORIZATION);
    Authenticator authenticator = OAuthServlet.getAuthenticator(_context);

    // Two authentication techniques here (preferring #1)
    //   1. Use Authentication header to find bearer token and validate to access user information beyond that in the bearer token
    //   2. OAuth2.0 resource request, uses non-bearer, non-OIDC OAuth2 token to access user information (still Authentication: Bearer header)
    // Third way to get user info with only user ID at /user/by-id

    if (authHeader == null) {
      return Response.status(Status.UNAUTHORIZED).build();
    }

    try {
      // option 1
      String token = OAuthClient.getTokenFromAuthHeader(authHeader);
      RequestingUser user = parseRequestingUser(token);
      return OAuthRequestHandler.handleUserInfoRequest(authenticator, user.getUserId(), user.isGuest());
    }
    catch (IllegalArgumentException badTokenException) {
      // bearer token parsing and validation failed; note in log and try traditional ID token
      LOG.warn("Bearer token failed with asymmetric signature validation (" + badTokenException.toString() + "); trying symmetric validation.");

      // option 2
      try {
        ApplicationConfig config = OAuthServlet.getApplicationConfig(_context);
        OAuthAccessResourceRequest oauthRequest = new OAuthAccessResourceRequest(_request, ParameterStyle.HEADER);
        return OAuthRequestHandler.handleUserInfoRequest(oauthRequest, authenticator, config.getIssuer(), config.getTokenExpirationSecs());
      }
      catch (OAuthProblemException e) {
        LOG.error("Problem with user request: ", e);
        return new OAuthResponseFactory().buildInvalidRequestResponse(e);
      }
    }
  }

  private RequestingUser parseRequestingUser(String bearerToken) {
    try {
      Key publicKey = OAuthServlet.getApplicationConfig(_context).getAsyncKeys().getPublic();
      // verify signature and create claims object
      Claims claims = Jwts.parserBuilder()
          .setSigningKey(publicKey)
          .build()
          .parseClaimsJws(bearerToken)
          .getBody();
      String userId = claims.getSubject();
      boolean isGuest = claims.get(IdTokenFields.is_guest.name(), Boolean.class);
      return new RequestingUser(userId, isGuest);
    }
    catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException e) {
      throw new IllegalArgumentException(e.getClass().getSimpleName() + ", Could not parse JWT; " + e.getMessage());
    }
  }

  @POST
  @Path(Endpoints.USER_CREATE)
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response createAccount(String body) {
    try {
      JsonObject input = Json.createReader(new StringReader(body)).readObject();
      if (!isUserManagementClient(input)) {
        return new OAuthResponseFactory().buildInvalidClientResponse();
      }

      // valid new user request from an allowed client
      UserPropertiesRequest userProps = new UserPropertiesRequest(input.getJsonObject("user"));
      Authenticator authenticator = OAuthServlet.getAuthenticator(_context);
      String initialPassword = authenticator.generateNewPassword();
      UserInfo newUser = authenticator.createUser(userProps, initialPassword);
      return Response.ok(OAuthRequestHandler.getUserInfoResponseString(newUser, Optional.of(initialPassword))).build();
    }
    catch (JsonParsingException | ClassCastException e) {
      throw new BadRequestException("Unable to parse client credentials", e);
    }
    catch (InvalidPropertiesException e) {
      // passed user properties were unacceptable for some reason
      return Response.status(HttpStatus.UNPROCESSABLE_CONTENT).entity(e.getMessage()).build();
    }
    catch (ConflictException e) {
      return Response.status(Status.CONFLICT).entity(e.getMessage()).build();
    }
  }

  @PUT
  @Path(Endpoints.USER_EDIT)
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response modifyAccount(String body) {
    try {
      JsonObject input = Json.createReader(new StringReader(body)).readObject();
      if (!isUserManagementClient(input)) {
        return new OAuthResponseFactory().buildInvalidClientResponse();
      }
      String authHeader = _request.getHeader(HttpHeaders.AUTHORIZATION);
      Authenticator authenticator = OAuthServlet.getAuthenticator(_context);
      if (authHeader == null) {
        return Response.status(Status.UNAUTHORIZED).build();
      }
      String token = OAuthClient.getTokenFromAuthHeader(authHeader);
      RequestingUser user = parseRequestingUser(token);
      if (user.isGuest()) {
        return Response.status(Status.FORBIDDEN).build();
      }

      // non guest user with proper credentials from an allowed client
      UserPropertiesRequest userProps = new UserPropertiesRequest(input.getJsonObject("user"));
      UserInfo modifiedUser = authenticator.modifyUser(user.getUserId(), userProps);
      return Response.ok(OAuthRequestHandler.getUserInfoResponseString(modifiedUser, Optional.empty())).build();

    }
    catch (JsonParsingException | ClassCastException e) {
      throw new BadRequestException("Unable to parse client credentials", e);
    }
    catch (InvalidPropertiesException e) {
      // passed user properties were unacceptable for some reason
      return Response.status(HttpStatus.UNPROCESSABLE_CONTENT).entity(e.getMessage()).build();
    }
    catch (ConflictException e) {
      return Response.status(Status.CONFLICT).entity(e.getMessage()).build();
    }
  }

  @POST
  @Path(Endpoints.PASSWORD_RESET)
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response resetPassword(String body) {
    try {
      JsonObject input = Json.createReader(new StringReader(body)).readObject();
      if (!isUserManagementClient(input)) {
        return new OAuthResponseFactory().buildInvalidClientResponse();
      }
      String loginName = input.getString("loginName");
      Authenticator authenticator = OAuthServlet.getAuthenticator(_context);
      Optional<UserInfo> userOpt = authenticator.getUserInfoByLoginName(loginName, DataScope.PROFILE);
      return userOpt.map(user -> {
        String newPassword = authenticator.generateNewPassword();
        authenticator.resetPassword(user.getUserId(), newPassword);
        return Response.ok(OAuthRequestHandler.getUserInfoResponseString(user, Optional.of(newPassword))).build();
      })
      .orElse(
        Response.status(HttpStatus.UNPROCESSABLE_CONTENT).entity("No user exists with login '" + loginName +"'.").build()
      );
    }
    catch (JsonParsingException | ClassCastException e) {
      throw new BadRequestException("Unable to parse client credentials", e);
    }
    catch (Exception e) {
      throw new RuntimeException("Unable to complete request", e);
    }
  }

  private boolean isUserManagementClient(JsonObject parentObject) {
    try {
      ClientValidator clientValidator = OAuthServlet.getClientValidator(_context);
      Entry<String,String> clientCreds = getClientCredentials(parentObject);
      return clientValidator.isValidProfileEditClient(clientCreds.getKey(), clientCreds.getValue());
    }
    catch (Exception e) {
      throw new BadRequestException("Unable to parse client credentials", e);
    }
  }

  private Entry<String, String> getClientCredentials(JsonObject parentObject) {
    JsonObject clientJson = parentObject.getJsonObject(OAuthClient.JSON_KEY_CREDENTIALS);
    return new SimpleEntry<>(
        clientJson.getString(OAuthClient.JSON_KEY_CLIENT_ID),
        clientJson.getString(OAuthClient.JSON_KEY_CLIENT_SECRET));
  }

  @POST
  @Path(Endpoints.USER_CHANGE_PW)
  public Response changePassword(String body) {

    // parse request params
    String username, password, newPassword;
    try {
      LOG.debug("Received body from client: " + body);
      JsonObject input = Json.createReader(new StringReader(body)).readObject();
      username = input.getString("username");
      password = input.getString("password");
      newPassword = input.getString("newPassword");
    }
    catch (NullPointerException | ClassCastException | JsonParsingException e) {
      return Response.status(Status.BAD_REQUEST).build();
    }

    // request properly formatted, check if credentials are valid
    Authenticator auth = OAuthServlet.getAuthenticator(_context);
    try {
      LOG.debug("Trying creds: " + username + "/" + password);
      Optional<String> userIdOpt = auth.isCredentialsValid(username, password);
      if (userIdOpt.isEmpty()) {
        // wrong password given for the passed user
        return Response.status(Status.FORBIDDEN).build();
      }
      // credentials valid; overwrite password
      //LOG.debug("Overwriting password: " + username + "/" + password);
      auth.overwritePassword(userIdOpt.get(), newPassword);
      return Response.ok().build();
    }
    catch (Exception e) {
      LOG.error("Error while processing password change request", e);
      return Response.serverError().build();
    }
  }

  @GET
  @Path(Endpoints.DISCOVERY)
  @Produces(MediaType.APPLICATION_JSON)
  public Response getConfiguration() {
    String baseUrl = _request.getRequestURL().toString();
    baseUrl = baseUrl.substring(0, baseUrl.indexOf(Endpoints.DISCOVERY));
    JsonArray responseTypes = buildArray("code", "id_token");
    JsonArray grantTypes = buildArray("authorization_code");
    JsonArray subjectTypes = buildArray("public");
    JsonArray supportedAlgorithms = buildArray(
        Signatures.ASYMMETRIC_KEY_ALGORITHM.getValue(),
        Signatures.SECRET_KEY_ALGORITHM.getValue()
    );
    JsonArray claims = buildArray(IdTokenFields
        .getNames().toArray(new String[0]));
    return Response.ok(
      OAuthRequestHandler.prettyPrintJsonObject(
        Json.createObjectBuilder()
          .add("issuer", OAuthServlet.getApplicationConfig(_context).getIssuer())
          .add("authorization_endpoint", baseUrl + Endpoints.AUTHORIZE)
          .add("token_endpoint", baseUrl + Endpoints.ID_TOKEN)
          .add("bearer_token_endpoint", baseUrl + Endpoints.BEARER_TOKEN)
          .add("userinfo_endpoint", baseUrl + Endpoints.USER_INFO)
          .add("jwks_uri", baseUrl + Endpoints.JWKS)
          .add("response_types_supported", responseTypes)
          .add("grant_types_supported", grantTypes)
          .add("subject_types_supported", subjectTypes)
          .add("id_token_signing_alg_values_supported", supportedAlgorithms)
          .add("claims_supported", claims)
          .build()
          .toString()
        )
      ).build();
  }

  private JsonArray buildArray(String... strings) {
    JsonArrayBuilder builder = Json.createArrayBuilder();
    for (String str : strings) {
      builder.add(str);
    }
    return builder.build();
  }

  @GET
  @Path(Endpoints.JWKS)
  @Produces(MediaType.APPLICATION_JSON)
  public Response getJwksJson() {
    return Response.ok(
      OAuthRequestHandler.prettyPrintJsonObject(
        Signatures.getJwksContent(
          OAuthServlet.getApplicationConfig(_context)
        ).toString())).build();
  }

  @POST
  @Path(Endpoints.QUERY_USERS)
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response queryAccountData(String body) {
    try {
      LOG.debug("Received body from client: " + body);
      JsonObject input = Json.createReader(new StringReader(body)).readObject();
      Entry<String,String> clientCreds = 
          input.containsKey(OAuthClient.JSON_KEY_CREDENTIALS)
          // use new client credentials format to determine validity
          ? getClientCredentials(input)
          // otherwise use oauth names; kept for backward compatibility with old clients (apollopatch)
          : new SimpleEntry<>(
              input.getString(OAuth.OAUTH_CLIENT_ID),
              input.getString(OAuth.OAUTH_CLIENT_SECRET));

      ClientValidator clientValidator = OAuthServlet.getClientValidator(_context);
      if (!clientValidator.isValidUserQueryClient(clientCreds.getKey(), clientCreds.getValue())) {
        return Response.status(Status.FORBIDDEN).build();
      }
      Authenticator auth = OAuthServlet.getAuthenticator(_context);
      JsonValue responseObject = auth.executeQuery(input.getJsonObject("query"));
      return Response.ok(responseObject.toString()).build();
    }
    catch (UnsupportedOperationException e) {
      return Response.status(Status.NOT_IMPLEMENTED).build();
    }
    catch (NullPointerException | ClassCastException | JsonParsingException | IllegalArgumentException e) {
      return Response.status(Status.BAD_REQUEST).entity(e.getMessage()).build();
    }
  }
}
