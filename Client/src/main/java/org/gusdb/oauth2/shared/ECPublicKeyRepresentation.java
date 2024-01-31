package org.gusdb.oauth2.shared;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Handles conversion of EC-521 public key to the following formats:
 * - ECPublicKey object
 * - Base64 encoded string
 * - X and Y EC Coordinates
 *
 * @author rdoherty
 */
public class ECPublicKeyRepresentation {

  public interface ECCoordinateStrings {
    String getX();
    String getY();
  }

  private final ECPublicKey _key;


  public ECPublicKeyRepresentation(ECPublicKey key) {
    _key = key;
  }

  public ECPublicKeyRepresentation(String base64encodedString) {
    _key = toECPublicKey(base64encodedString);
  }

  public ECPublicKeyRepresentation(String x, String y) {
    _key = toECPublicKey(x, y);
  }

  public ECPublicKey getPublicKey() {
    return _key;
  }

  public String getBase64String() {
    return Base64.getEncoder().encodeToString(_key.getEncoded());
  }

  public ECCoordinateStrings getCoordinates() {
    return toECCoordinates(_key);
  }

  private static ECPublicKey toECPublicKey(String base64encodedString) {
    try {
      byte[] publicBytes = Base64.getDecoder().decode(base64encodedString);
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("EC");
      return (ECPublicKey)keyFactory.generatePublic(keySpec);
    }
    catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException("Unable to decode public key", e);
    }
  }

  private static ECPublicKey toECPublicKey(String xStr, String yStr) {
    try {
      String algorithm = "EC";
      String jcaName = "secp521r1";

      BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode(xStr));
      BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode(yStr));

      AlgorithmParameters algParams = AlgorithmParameters.getInstance(algorithm);
      algParams.init(new ECGenParameterSpec(jcaName));
      ECParameterSpec spec = algParams.getParameterSpec(ECParameterSpec.class);

      ECPoint point = new ECPoint(x, y);
      ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, spec);

      return (ECPublicKey)KeyFactory.getInstance(algorithm).generatePublic(pubSpec);
    }
    catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException e) {
      throw new RuntimeException("Unable to decode public key", e);
    }
  }

  private static ECCoordinateStrings toECCoordinates(ECPublicKey key) {
    ECParameterSpec spec = key.getParams();
    EllipticCurve curve = spec.getCurve();
    ECPoint point = key.getW();

    int fieldSize = curve.getField().getFieldSize();
    String x = toOctetString(fieldSize, point.getAffineX());
    String y = toOctetString(fieldSize, point.getAffineY());
  
    return new ECCoordinateStrings() {
      @Override public String getX() { return x; }
      @Override public String getY() { return y; }
    };
  }

  // Needed until we upgrade JJWT past 0.11.5; copied and modified from
  // https://github.com/jwtk/jjwt/blob/992d75d0b4ef4349646a89b75c5e6a3bcf9aa8b2/impl/src/main/java/io/jsonwebtoken/impl/security/AbstractEcJwkFactory.java#L76
  private static String toOctetString(int fieldSize, BigInteger coordinate) {
    byte[] bytes = convertToUBytes(coordinate);
    int mlen = (int) Math.ceil(fieldSize / 8d);
    if (mlen > bytes.length) {
        byte[] m = new byte[mlen];
        System.arraycopy(bytes, 0, m, mlen - bytes.length, bytes.length);
        bytes = m;
    }
    return Base64.getUrlEncoder().encodeToString(bytes);
  }

  // Needed until we can upgrade JJWT from 0.11.5; copied and modified from
  // https://github.com/jwtk/jjwt/blob/master/impl/src/main/java/io/jsonwebtoken/impl/lang/BigIntegerUBytesConverter.java
  private static byte[] convertToUBytes(BigInteger bigInt) {
    Objects.requireNonNull(bigInt, "BigInteger argument cannot be null.");
    if (BigInteger.ZERO.compareTo(bigInt) > 0) {
        throw new IllegalArgumentException(NEGATIVE_MSG);
    }

    final int bitLen = bigInt.bitLength();
    final byte[] bytes = bigInt.toByteArray();
    // round bitLen. This gives the minimal number of bytes necessary to represent an unsigned byte array:
    final int unsignedByteLen = Math.max(1, (bitLen + 7) / Byte.SIZE);

    if (bytes.length == unsignedByteLen) { // already in the form we need
        return bytes;
    }
    //otherwise, we need to strip the sign byte (start copying at index 1 instead of 0):
    byte[] ubytes = new byte[unsignedByteLen];
    System.arraycopy(bytes, 1, ubytes, 0, unsignedByteLen);
    return ubytes;
  }

   private static final String NEGATIVE_MSG =
       "JWA Base64urlUInt values MUST be >= 0 (non-negative) per the 'Base64urlUInt' definition in " +
           "[JWA RFC 7518, Section 2](https://www.rfc-editor.org/rfc/rfc7518.html#section-2)";

}
