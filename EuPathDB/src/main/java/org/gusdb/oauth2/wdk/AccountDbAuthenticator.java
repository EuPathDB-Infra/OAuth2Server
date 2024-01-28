package org.gusdb.oauth2.wdk;

import static org.gusdb.fgputil.FormatUtil.getInnerClassLog4jName;

import java.net.URI;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.json.stream.JsonParsingException;

import org.apache.log4j.Logger;
import org.gusdb.fgputil.accountdb.AccountManager;
import org.gusdb.fgputil.accountdb.UserProfile;
import org.gusdb.fgputil.accountdb.UserPropertyName;
import org.gusdb.fgputil.db.platform.SupportedPlatform;
import org.gusdb.fgputil.db.pool.ConnectionPoolConfig;
import org.gusdb.fgputil.db.pool.DatabaseInstance;
import org.gusdb.fgputil.db.pool.SimpleDbConfig;
import org.gusdb.fgputil.functional.Functions;
import org.gusdb.oauth2.Authenticator;
import org.gusdb.oauth2.InitializationException;
import org.gusdb.oauth2.UserInfo;
import org.gusdb.oauth2.service.UserPropertiesRequest;

public class AccountDbAuthenticator implements Authenticator {

  private static final Logger LOG = Logger.getLogger(AccountDbAuthenticator.class);

  // create specially scoped Logger to write the login recording log
  private static class LoginLogger {}
  private static final Logger LOGIN_LOG = Logger.getLogger(getInnerClassLog4jName(LoginLogger.class));

  private static enum JsonKey {
    login,
    password,
    connectionUrl,
    platform,
    poolSize,
    schema
  }

  private static final List<UserPropertyName> USER_PROPERTY_DEFS = List.of(
      new UserPropertyName("username", "username", false),
      new UserPropertyName("firstName", "first_name", true),
      new UserPropertyName("middleName", "middle_name", false),
      new UserPropertyName("lastName", "last_name", true),
      new UserPropertyName("organization", "organization", true),
      new UserPropertyName("interests", "interests", false)
  );

  private DatabaseInstance _accountDb;
  private String _schema;

  @Override
  public void initialize(JsonObject configJson) throws InitializationException {
    ConnectionPoolConfig dbConfig = SimpleDbConfig.create(
        SupportedPlatform.toPlatform(configJson.getString(JsonKey.platform.name())),
        configJson.getString(JsonKey.connectionUrl.name()),
        configJson.getString(JsonKey.login.name()),
        configJson.getString(JsonKey.password.name()),
        (short)configJson.getInt(JsonKey.poolSize.name()));
    String schema = configJson.getString(JsonKey.schema.name());
    initialize(dbConfig, schema);
  }

  protected void initialize(ConnectionPoolConfig dbConfig, String schema) {
    LOG.info("Initializing database using: " + dbConfig);
    _accountDb = new DatabaseInstance(dbConfig, true);
    if (!schema.isEmpty() && !schema.endsWith(".")) schema += ".";
    _schema = schema;
  }

  // WDK uses email and password
  @Override
  public Optional<String> isCredentialsValid(String username, String password) throws Exception {
    return Optional.ofNullable(
        new AccountManager(_accountDb, _schema, USER_PROPERTY_DEFS).getUserProfile(username, password))
      .map(profile -> profile.getUserId().toString());
  }

  @Override
  public Optional<UserInfo> getUserInfoByLoginName(String loginName, DataScope scope) throws Exception {
    return getUserInfo(new AccountManager(_accountDb, _schema, USER_PROPERTY_DEFS).getUserProfileByUsernameOrEmail(loginName), scope);
  }

  @Override
  public Optional<UserInfo> getUserInfoByUserId(String userId, DataScope scope) throws Exception {
    return getUserInfo(new AccountManager(_accountDb, _schema, USER_PROPERTY_DEFS).getUserProfile(Long.valueOf(userId)), scope);
  }

  @Override
  public void resetPassword(String userId, String newPassword) {
    new AccountManager(_accountDb, _schema, USER_PROPERTY_DEFS).updatePassword(Long.valueOf(userId), newPassword);
  }

  @Override
  public String generateNewPassword() {
    // generate a random password of 12 characters, each in the range [0-9A-Za-z]
    StringBuilder buffer = new StringBuilder();
    Random rand = new Random();
    for (int i = 0; i < 12; i++) {
      int value = rand.nextInt(62);
      if (value < 10) { // number
        buffer.append(value);
      }
      else if (value < 36) { // upper case letters
        buffer.append((char) ('A' + value - 10));
      }
      else { // lower case letters
        buffer.append((char) ('a' + value - 36));
      }
    }
    return buffer.toString();
  }

  private Optional<UserInfo> getUserInfo(UserProfile profile, DataScope scope) {
    return Optional.ofNullable(profile).map(p -> createUserInfoObject(p, true, scope));
  }

  private UserInfo createUserInfoObject(UserProfile profile, boolean isEmailVerified, DataScope scope) {
    return new UserInfo() {
      @Override
      public String getUserId() {
        return String.valueOf(profile.getUserId());
      }
      @Override
      public boolean isGuest() {
        return profile.isGuest();
      }
      @Override
      public String getEmail() {
        // username is email address in Account DB
        return profile.getEmail();
      }
      @Override
      public boolean isEmailVerified() {
        return isEmailVerified;
      }
      @Override
      public String getPreferredUsername() {
        // stable value that EuPathDB can use to identify this user
        return profile.getStableId();
      }
      @Override
      public String getSignature() {
        return profile.getSignature();
      }
      @Override
      public Map<String, JsonValue> getSupplementalFields() {
        JsonObjectBuilder builder = Json.createObjectBuilder()
            .add("name", getDisplayName(profile.getProperties()))
            .add("organization", profile.getProperties().get("organization"));
        if (scope == DataScope.PROFILE) builder
            .add("firstName", profile.getProperties().get("firstName"))
            .add("middleName", profile.getProperties().get("middleName"))
            .add("lastName", profile.getProperties().get("lastName"))
            .add("username", profile.getProperties().get("username"))
            .add("interests", profile.getProperties().get("interests"));
        JsonObject json = builder.build();
        // convert JSON object to map of String -> JsonValue
        Map<String,JsonValue> map = new HashMap<>();
        for (String key : json.keySet()) {
          // we know they are all strings 
          map.put(key, json.getJsonString(key));
        }
        return map;
      }
    };
  }

  // protected so TestAuthenticator can override
  protected UserProfile getUserProfile(String userId) {
    return new AccountManager(_accountDb, _schema, USER_PROPERTY_DEFS).getUserProfile(Long.valueOf(userId));
  }

  private static String getDisplayName(Map<String,String> userProperties) {
    String firstName = userProperties.get("firstName");
    String middleName = userProperties.get("middleName");
    String lastName = userProperties.get("lastName");
    String name = null;
    if (firstName != null && !firstName.isEmpty()) name = firstName;
    if (middleName != null && !middleName.isEmpty()) {
      name = (name == null ? middleName : name + " " + middleName);
    }
    if (lastName != null && !lastName.isEmpty()) {
      name = (name == null ? lastName : name + " " + lastName);
    }
    return name;
  }

  @Override
  public boolean supportsGuests() {
    return true;
  }

  /**
   * @return a new guest ID
   */
  @Override
  public String getNextGuestId() {
    try {
      return new AccountManager(_accountDb, _schema, USER_PROPERTY_DEFS).createGuestAccount("guest").getUserId().toString();
    }
    catch (SQLException e) {
      throw new RuntimeException("Unable to generate next guest ID", e);
    }
  }

    @Override
  public void close() {
    if (_accountDb != null) {
      try {
        _accountDb.close();
      }
      catch (Exception e) {
        throw new RuntimeException("Unable to properly close configured database instance", e);
      }
    }
  }

  @Override
  public void overwritePassword(String username, String newPassword) throws Exception {
    UserProfile profile = getUserProfile(username);
    new AccountManager(_accountDb, _schema, USER_PROPERTY_DEFS).updatePassword(profile.getUserId(), newPassword);
  }

  @Override
  public JsonValue executeQuery(JsonObject querySpec)
      throws UnsupportedOperationException, IllegalArgumentException {
    try {
      if ((!querySpec.containsKey("userId") && !querySpec.containsKey("userIds")) ||
          ( querySpec.containsKey("userId") &&  querySpec.containsKey("userIds"))) {
        throw new IllegalArgumentException("Query must contain exactly one of ['userId', 'userIds']");
      }
      AccountManager acctDb = new AccountManager(_accountDb, _schema, USER_PROPERTY_DEFS);
      if (querySpec.containsKey("userId")) {
        long requestedUserId = Long.valueOf(querySpec.getInt("userId"));
        return getUserJson(acctDb, requestedUserId);
      }
      else {
        JsonArray inputArray = querySpec.getJsonArray("userIds");
        JsonArrayBuilder outputArray = Json.createArrayBuilder();
        for (int i = 0; i < inputArray.size(); i++) {
          JsonObject userObj = getUserJson(acctDb, Long.valueOf(inputArray.getInt(i)));
          outputArray.add(userObj);
        }
        return outputArray.build();
      }
    }
    catch (JsonParsingException e) {
      throw new IllegalArgumentException("Illegal query; " + e.getMessage());
    }
  }

  private JsonObject getUserJson(AccountManager acctDb, long requestedUserId) {
    UserProfile user = acctDb.getUserProfile(requestedUserId);
    if (user == null) {
      return Json.createObjectBuilder()
          .add("userId", requestedUserId)
          .add("found", false)
          .build();
    }
    else {
      return Json.createObjectBuilder()
          .add("userId", requestedUserId)
          .add("found", true)
          .add("isGuest", false)
          .add("email", user.getEmail())
          .add("name", getDisplayName(user.getProperties()))
          .add("organization", user.getProperties().get("organization"))
          .build();
    }
  }

  @Override
  public void logSuccessfulLogin(String loginName, String userId, String clientId, String redirectUri, String requestingIpAddress) {
    LOGIN_LOG.info(requestingIpAddress + " " + clientId + " " + getHost(redirectUri) + " " + userId + " " + loginName);
  }

  private static String getHost(String uriStr) {
    try {
      return new URI(uriStr).getHost();
    }
    catch(Exception e) {
      LOG.error("Unable to parse passed URI: " + uriStr);
      return "unknown";
    }
  }

  @Override
  public UserInfo createUser(UserPropertiesRequest userProps, String initialPassword) {
    AccountManager accountMgr = new AccountManager(_accountDb, _schema, USER_PROPERTY_DEFS);
    validateUserProps(accountMgr, userProps);
    UserProfile newUser = Functions.mapException(
        () -> accountMgr.createAccount(userProps.getEmail(), initialPassword, userProps),
        e -> new RuntimeException(e)); // all exceptions at this point are 500s
    return createUserInfoObject(newUser, false, DataScope.PROFILE);
  }

  private void validateUserProps(AccountManager accountMgr, UserPropertiesRequest userProps) {

    // check email for uniqueness and format
    userProps.setEmail(validateAndFormatEmail(userProps.getEmail(), accountMgr));

    // if user supplied a username, make sure it is unique
    if (userProps.containsKey(AccountManager.USERNAME_PROPERTY_KEY)) {
      String username = userProps.get(AccountManager.USERNAME_PROPERTY_KEY);
      // check whether the username exists in the database already; if so, the operation fails
      if (accountMgr.getUserProfileByUsername(username) != null) {
        throw new IllegalArgumentException("The username '" + username + "' is already in use. " + "Please choose another one.");
      }
    }

    // make sure required props are present; trimming of unsupported keys is done in AccountManager
    // TODO: move this check into AccountManager
    for (UserPropertyName prop : USER_PROPERTY_DEFS) {
      if (prop.isRequired() && (!userProps.containsKey(prop.getName()) || userProps.get(prop.getName()).isBlank())) {
        throw new IllegalArgumentException("User property '" + prop.getName() + "' cannot be empty.");
      }
    }
  }

  private static String validateAndFormatEmail(String email, AccountManager accountMgr) {
    // trim and validate passed email address and extract stable name
    if (email == null)
      throw new IllegalArgumentException("The user's email cannot be empty.");
    // format the info
    email = AccountManager.trimAndLowercase(email);
    if (email.isEmpty())
      throw new IllegalArgumentException("The user's email cannot be empty.");
    int atSignIndex = email.indexOf("@");
    if (atSignIndex < 1) // must be present and not the first char
      throw new IllegalArgumentException("The user's email address is invalid.");
    // check whether the user exist in the database already; if email exists, the operation fails
    if (accountMgr.getUserProfileByEmail(email) != null)
      throw new IllegalArgumentException("The email '" + email + "' has already been registered. " + "Please choose another.");
    return email;
  }

  @Override
  public UserInfo modifyUser(String userIdStr, UserPropertiesRequest userProps) {
    AccountManager accountMgr = new AccountManager(_accountDb, _schema, USER_PROPERTY_DEFS);
    validateUserProps(accountMgr, userProps);
    long userId = Long.valueOf(userIdStr);
    Functions.mapException(
        () -> accountMgr.saveUserProfile(userId, userProps.getEmail(), userProps),
        e -> new RuntimeException(e)); // all exceptions at this point are 500s
    // after saving, read object back out of DB
    UserProfile user = accountMgr.getUserProfile(userId);
    return createUserInfoObject(user, true, DataScope.PROFILE);
  }

  @Override
  public UserInfo getGuestProfileInfo(String userId) {
    UserProfile guest = AccountManager.createGuestProfile("guest", Long.valueOf(userId), new Date());
    return createUserInfoObject(guest, false, DataScope.PROFILE);
  }

}
