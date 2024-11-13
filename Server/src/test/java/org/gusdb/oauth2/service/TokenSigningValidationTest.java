package org.gusdb.oauth2.service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Set;
import java.util.function.Supplier;

import jakarta.json.Json;
import jakarta.json.JsonObject;

import org.gusdb.oauth2.exception.CryptoException;
import org.gusdb.oauth2.shared.ECPublicKeyRepresentation;
import org.gusdb.oauth2.shared.Signatures;
import org.gusdb.oauth2.shared.SigningKeyStore;
import org.gusdb.oauth2.shared.ECPublicKeyRepresentation.ECCoordinateStrings;
import org.gusdb.oauth2.tools.KeyGenerator;
import org.junit.Assert;
import org.junit.Test;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.TextCodec;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

// suppress deprecation warnings; we know the legacy method is deprecated- that's why we're testing the new method :)
@SuppressWarnings("deprecation")
public class TokenSigningValidationTest {

  // symmetric token config
  private static final String MANUAL_CLIENT_ID_FAIL = "manualSecretClientFail";
  private static final String MANUAL_CLIENT_SECRET_FAIL = "12345678901234567890123456";

  private static final String MANUAL_CLIENT_ID = "manualSecretClient";
  private static final String MANUAL_CLIENT_SECRET = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";

  private static final String AUTO_CLIENT_ID = "autoSecretClient";
  private static String AUTO_CLIENT_SECRET; // will be assigned during key store creation

  // asymmetric token config
  private static final String KEY_PAIR_RANDOM_SEED = "ne2OCyFSoXXtLCR2RQuUsaqaWBmnwufNNhCyv6KygkwDDpILeOv67MEecKguBFrhqyiYO/UM6JJzVd5Xh3JwSA==";

  // claims object to be encoded/signed/verified/decoded
  private static final JsonObject DUMMY_CLAIMS = Json.createObjectBuilder().add("sub", "myUserId").build();

  // key store object for signing JWT
  private static final SigningKeyStore KEY_STORE = ((Supplier<SigningKeyStore>)() -> {
    try {
      // create a key store
      SigningKeyStore keyStore = new SigningKeyStore(KEY_PAIR_RANDOM_SEED);

      // assign manually generated HMAC client secrets
      keyStore.setClientSigningKeys(MANUAL_CLIENT_ID, Set.of(MANUAL_CLIENT_SECRET));

      // assign auto-generated HMAC client secret
      Key key = Keys.secretKeyFor(Signatures.SECRET_KEY_ALGORITHM);
      AUTO_CLIENT_SECRET = KeyGenerator.toOutputString(key);
      keyStore.setClientSigningKeys(AUTO_CLIENT_ID, Set.of(AUTO_CLIENT_SECRET));
      
      byte[] privateKeyBytes = keyStore.getAsyncKeys().getPrivate().getEncoded();
      byte[] publicKeyBytes = keyStore.getAsyncKeys().getPublic().getEncoded();
      System.out.println("Generated the following key pair in base64:\nprivate\n" +
          new String(Base64.getEncoder().encode(privateKeyBytes), StandardCharsets.UTF_8) + "\npublic\n" +
          new String(Base64.getEncoder().encode(publicKeyBytes), StandardCharsets.UTF_8));
      System.out.println("Generated the following key pair in hex:\nprivate\n" +
          String.format("%040x", new BigInteger(1, privateKeyBytes)) + "\npublic\n" +
          String.format("%040x", new BigInteger(1, publicKeyBytes)));
      return keyStore;
    }
    catch (CryptoException e) {
      throw new RuntimeException(e);
    }
  }).get();

  private static final String BAD_PUBLIC_KEY = ((Supplier<String>)() -> {
    try {
      return Base64.getEncoder().encodeToString(new SigningKeyStore(KEY_PAIR_RANDOM_SEED + 1).getAsyncKeys().getPublic().getEncoded());
    }
    catch (Exception e) { throw new RuntimeException(e); }
  }).get();

  @Test(expected = CryptoException.class)
  public void testLegacySymmetricTokenValidatorManualFail() throws Exception {
    KEY_STORE.setClientSigningKeys(MANUAL_CLIENT_ID_FAIL, Set.of(MANUAL_CLIENT_SECRET_FAIL));
    testLegacySymmetricTokenValidator(MANUAL_CLIENT_ID_FAIL, MANUAL_CLIENT_SECRET_FAIL, "manual_fail");
  }

  @Test
  public void testLegacySymmetricTokenValidatorManualSuccess() throws Exception {
    testLegacySymmetricTokenValidator(MANUAL_CLIENT_ID, MANUAL_CLIENT_SECRET, "manual");
  }

  @Test
  public void testLegacySymmetricTokenValidatorAuto() throws Exception {
    testLegacySymmetricTokenValidator(AUTO_CLIENT_ID, AUTO_CLIENT_SECRET, "auto");
  }

  public void testLegacySymmetricTokenValidator(String clientId, String clientSecret, String testType) throws Exception {
    // create a signed token
    String symmetricToken = Signatures.SECRET_KEY_SIGNER.getSignedEncodedToken(DUMMY_CLAIMS, KEY_STORE, clientId, clientSecret);

    // encode the key as a base64 string
    String encodedKey = TextCodec.BASE64.encode(clientSecret);
    System.out.println(testType + " legacy: " + encodedKey);

    // convert the key back to bytes
    byte[] keyBytes = Decoders.BASE64.decode(encodedKey);

    // verify signature and create claims object
    Claims claims = Jwts.parser()
        .setSigningKey(keyBytes)
        .parseClaimsJws(symmetricToken)
        .getBody();

    // check subject claim
    Assert.assertEquals("myUserId", claims.getSubject());

  }

  @Test(expected = CryptoException.class)
  public void testNewSymmetricTokenValidatorManualFail() throws Exception {
    KEY_STORE.setClientSigningKeys(MANUAL_CLIENT_ID_FAIL, Set.of(MANUAL_CLIENT_SECRET_FAIL));
    testNewSymmetricTokenValidatorManual(MANUAL_CLIENT_ID_FAIL, MANUAL_CLIENT_SECRET_FAIL, "manual_fail");
  }

  @Test
  public void testNewSymmetricTokenValidatorManual() throws Exception {
    testNewSymmetricTokenValidatorManual(MANUAL_CLIENT_ID, MANUAL_CLIENT_SECRET, "manual");
  }

  @Test
  public void testNewSymmetricTokenValidatorAuto() throws Exception {
    testNewSymmetricTokenValidatorManual(AUTO_CLIENT_ID, AUTO_CLIENT_SECRET, "auto");
  }

  public void testNewSymmetricTokenValidatorManual(String clientId, String clientSecret, String testType) throws Exception {

    // create a signed token
    String symmetricToken = Signatures.SECRET_KEY_SIGNER.getSignedEncodedToken(DUMMY_CLAIMS, KEY_STORE, clientId, clientSecret);

    // encode the key as a base64 string
    byte[] unencodedKey = clientSecret.getBytes(StandardCharsets.UTF_8);
    String encodedKeyStr = Base64.getEncoder().encodeToString(unencodedKey);
    System.out.println(testType + " new: " + encodedKeyStr);

    // convert the key back to bytes
    byte[] keyBytes = Base64.getDecoder().decode(encodedKeyStr);

    // verify signature and create claims object
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(keyBytes)
        .build()
        .parseClaimsJws(symmetricToken)
        .getBody();

    // check subject claim
    Assert.assertEquals("myUserId", claims.getSubject());

  }

  @Test
  public void testAsymmetricKeyTokenValidator() throws Exception {
    testAsymmetricKeyTokenValidator(false);
  }

  @Test(expected=SignatureException.class)
  public void testAsymmetricKeyTokenValidatorFail() throws Exception {
    testAsymmetricKeyTokenValidator(true);
  }

  public static void testAsymmetricKeyTokenValidator(boolean fail) throws Exception {
    // create a signed token
    String asymmetricToken = Signatures.ASYMMETRIC_KEY_SIGNER.getSignedEncodedToken(DUMMY_CLAIMS, KEY_STORE, MANUAL_CLIENT_ID, null);
    System.out.println(Signatures.getJwksContent(KEY_STORE));

    // encode the public key for distribution
    String encodedKeyStr = new ECPublicKeyRepresentation((ECPublicKey)KEY_STORE.getAsyncKeys().getPublic()).getBase64String();

    // add salt if failure desired
    if (fail) encodedKeyStr += "af";

    // convert the key string to a public key object
    PublicKey publicKey = new ECPublicKeyRepresentation(fail ? BAD_PUBLIC_KEY : encodedKeyStr).getPublicKey();

    // verify signature and create claims object
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(publicKey)
        .build()
        .parseClaimsJws(asymmetricToken)
        .getBody();

    // check subject claim
    Assert.assertTrue(claims.containsKey("sub"));
    Assert.assertEquals("myUserId", claims.getSubject());

  }

  @Test
  public void testAsymmetricCoordinatesTokenValidator() throws Exception {

    // create a signed token
    String asymmetricToken = Signatures.ASYMMETRIC_KEY_SIGNER.getSignedEncodedToken(DUMMY_CLAIMS, KEY_STORE, MANUAL_CLIENT_ID, null);
    System.out.println(Signatures.getJwksContent(KEY_STORE));

    // encode the public key into coordinates for distribution
    ECCoordinateStrings publicKeyCoords = new ECPublicKeyRepresentation((ECPublicKey)KEY_STORE.getAsyncKeys().getPublic()).getCoordinates();
    String x = publicKeyCoords.getX();
    String y = publicKeyCoords.getY();

    // convert the coordinate strings ito a public key object
    PublicKey publicKey = new ECPublicKeyRepresentation(x, y).getPublicKey();

    // verify signature and create claims object
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(publicKey)
        .build()
        .parseClaimsJws(asymmetricToken)
        .getBody();

    // check subject claim
    Assert.assertTrue(claims.containsKey("sub"));
    Assert.assertEquals("myUserId", claims.getSubject());

  }
}
