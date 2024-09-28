package org.gusdb.oauth2.eupathdb;

import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonObject;

import org.gusdb.oauth2.Authenticator;
import org.gusdb.oauth2.Authenticator.DataScope;
import org.gusdb.oauth2.config.ApplicationConfig;
import org.gusdb.oauth2.service.token.TokenFactory;
import org.gusdb.oauth2.service.token.TokenStore.IdTokenParams;
import org.gusdb.oauth2.shared.ECPublicKeyRepresentation;
import org.gusdb.oauth2.shared.Signatures;
import org.gusdb.oauth2.shared.SigningKeyStore;
import org.gusdb.oauth2.tools.KeyPairReader;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class BearerTokenGenerator extends ToolBase {

  private static final String PROP_KEYSTORE_FILE = "keyStoreFile";
  private static final String PROP_KEYSTORE_PASSPHRASE = "keyStorePassPhrase";
  private static final String PROP_ACCOUNTDB_LOGIN = "accountDbLogin";
  private static final String PROP_ACCOUNTDB_PASSWORD = "accountDbPassword";
  private static final String PROP_LOGIN_NAME = "loginName";
  private static final String PROP_DB_PLATFORM = "dbPlatform";

  public static void main(String[] args) throws Exception {
    new BearerTokenGenerator(args).execute();
  }

  public BearerTokenGenerator(String[] args) {
    super(args, new String[] { PROP_KEYSTORE_FILE, PROP_KEYSTORE_PASSPHRASE, PROP_ACCOUNTDB_LOGIN, PROP_ACCOUNTDB_PASSWORD, PROP_LOGIN_NAME, PROP_DB_PLATFORM });
  }

  public void execute() throws Exception {

    String keyStoreFile = findProp(PROP_KEYSTORE_FILE);
    String keyStorePassPhrase = findProp(PROP_KEYSTORE_PASSPHRASE);
    String accountDbLogin = findProp(PROP_ACCOUNTDB_LOGIN);
    String accountDbPassword = findProp(PROP_ACCOUNTDB_PASSWORD);
    String loginName = findProp(PROP_LOGIN_NAME);
    String platform = findProp(PROP_DB_PLATFORM);

    SigningKeyStore keyStore = new SigningKeyStore(new KeyPairReader().readKeyPair(Paths.get(keyStoreFile), keyStorePassPhrase));

    // dummy up a client; SigningKeyStore requires >0 but will not be used here
    keyStore.setClientSigningKeys("abc", Set.of("mug2kfCI8qhXzrnuE/nh1gK9JbSFaXaih+zdsfD8io25MWH4b3V5u+U8E7SW4x7iBAHdq6yWWrF/TP9p098lfQ=="));

    // generate a new token for this account
    String token = generateToken(keyStore, accountDbLogin, accountDbPassword, loginName, platform);
    System.out.println("Bearer Token\n\n" + token + "\n");

    // verify token using same method as the client
    System.out.println("JWKS content: " + Signatures.getJwksContent(keyStore));
    ECPublicKey publicKeyIn = (ECPublicKey)keyStore.getAsyncKeys().getPublic();
    String publicKeyString = new ECPublicKeyRepresentation(publicKeyIn).getBase64String();
    System.out.println("Public key string:\n\n" + publicKeyString);

    PublicKey publicKeyOut = new ECPublicKeyRepresentation(publicKeyString).getPublicKey();

    // verify signature and create claims object
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(publicKeyOut)
        .build()
        .parseClaimsJws(token)
        .getBody();

    System.out.println("Subject after parsing token: " + claims.getSubject());
  }

  private static String generateToken(SigningKeyStore keyStore, String accountDbLogin, String accountDbPassword, String loginName, String dbPlatform) throws Exception {

    JsonObject authenticatorConfig = Json.createObjectBuilder()
        .add("login", accountDbLogin)
        .add("password", accountDbPassword)
        .add("connectionUrl", "jdbc:oracle:thin:@localhost:5011/acctdb.upenn.edu")
        .add("platform", dbPlatform)
        .add("poolSize", 1)
        .add("schema", "useraccounts.")
        .build();

    try (Authenticator authenticator = new AccountDbAuthenticator()) {

      authenticator.initialize(authenticatorConfig);

      IdTokenParams params = new IdTokenParams("apiComponentSite", null);

      JsonObject tokenJson = TokenFactory.createTokenJson(authenticator, loginName, params,
          "https://eupathdb.org/oauth", ApplicationConfig.DEFAULT_BEARER_TOKEN_EXPIRATION_SECS, DataScope.BEARER_TOKEN);

      return Signatures.ASYMMETRIC_KEY_SIGNER.getSignedEncodedToken(tokenJson, keyStore, params.getClientId(), null);
    }
  }
}
