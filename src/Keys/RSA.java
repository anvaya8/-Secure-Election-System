package Keys;

import java.io.*;
import java.math.BigInteger;
import java.util.Random;

public class RSA {

  public static byte[] cipher(String input, Key key) throws Exception {
    return cipher(input.getBytes(), key);
  }

  public static byte[] cipher(byte[] inputBytes, Key key) throws Exception {
    byte[] inputWithPrefix = new byte[inputBytes.length + 1];
    inputWithPrefix[0] = 0;
    System.arraycopy(inputBytes, 0, inputWithPrefix, 1, inputBytes.length);

    byte[] encrypted = new BigInteger(inputWithPrefix).modPow(key.getKey(), key.getN()).toByteArray();

    if (encrypted[0] != 0) {
      return encrypted;
    }

    byte[] trimmed = new byte[encrypted.length - 1];
    System.arraycopy(encrypted, 1, trimmed, 0, trimmed.length);
    return trimmed;
  }

  public static KeyPair generateKeys(BigInteger p, BigInteger q) {
    BigInteger one = BigInteger.ONE;
    BigInteger n = p.multiply(q);
    BigInteger phi = p.subtract(one).multiply(q.subtract(one));
    BigInteger e = relativePrime(phi);
    BigInteger d = e.modInverse(phi);
    return new KeyPair(new PrivateKey(d, n), new PublicKey(e, n));
  }

  public static void main(String[] args) throws Exception {
    int bitLength = Integer.parseInt(System.getProperty("prime_size", "256"));
    int certainty = Integer.parseInt(System.getProperty("prime_certainty", "5"));

    BigInteger p = new BigInteger(bitLength, certainty, new Random());
    BigInteger q = new BigInteger(bitLength, certainty, new Random());

    KeyPair keys = generateKeys(p, q);

    System.out.println(keys);

    saveKey("private_key.txt", keys.getPrivateKey());
    saveKey("public_key.txt", keys.getPublicKey());

    if (args.length == 2) {
      byte[] original = args[1].getBytes();
      byte[] encrypted = cipher(original, keys.getPublicKey());
      byte[] decrypted = cipher(encrypted, keys.getPrivateKey());

      System.out.println("Encrypted then Decrypted: " + new String(decrypted));
    }
  }

  public static void saveKey(String filename, Key key) {
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
      writer.write(key.toString());
    } catch (IOException e) {
      System.out.println("Unable to save key: " + e.getMessage());
    }
  }

  private static BigInteger relativePrime(BigInteger phi) {
    Random rand = new Random();
    BigInteger candidate;
    do {
      candidate = new BigInteger(phi.bitLength(), rand).mod(phi);
    } while (!phi.gcd(candidate).equals(BigInteger.ONE));
    return candidate;
  }

  public static class Key {
    protected BigInteger key;
    protected BigInteger n;

    public Key() {
      this(BigInteger.ZERO, BigInteger.ZERO);
    }

    public Key(BigInteger key, BigInteger n) {
      this.key = key;
      this.n = n;
    }

    protected BigInteger getKey() {
      return key;
    }

    protected BigInteger getN() {
      return n;
    }

    public void read(InputStream in) throws IOException {
      int ch;
      while ((ch = in.read()) != 123) {
        if (ch == -1) throw new EOFException("Unexpected EOF");
      }

      StringBuilder sb = new StringBuilder();
      while ((ch = in.read()) != ',') {
        if (ch == -1) throw new EOFException("Unexpected EOF");
        sb.append((char) ch);
      }
      key = new BigInteger(sb.toString());

      sb.setLength(0);
      while ((ch = in.read()) != 125) {
        if (ch == -1) throw new EOFException("Unexpected EOF");
        sb.append((char) ch);
      }
      n = new BigInteger(sb.toString());
    }

    public void read(byte[] data) throws IOException {
      read(new ByteArrayInputStream(data));
    }

    public String toString() {
      return "{" + key + "," + n + "}";
    }
  }

  public static class PublicKey extends Key {
    public PublicKey(BigInteger key, BigInteger n) {
      super(key, n);
    }

    public PublicKey(InputStream in) throws IOException {
      read(in);
    }

    public PublicKey(byte[] data) throws IOException {
      read(data);
    }
  }

  public static class PrivateKey extends Key {
    public PrivateKey(BigInteger key, BigInteger n) {
      super(key, n);
    }

    public PrivateKey(InputStream in) throws IOException {
      read(in);
    }

    public PrivateKey(byte[] data) throws IOException {
      read(data);
    }
  }

  public static class KeyPair {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public KeyPair(PrivateKey privateKey, PublicKey publicKey) {
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
      return privateKey;
    }

    public PublicKey getPublicKey() {
      return publicKey;
    }

    public String toString() {
      return "KR=" + privateKey + System.lineSeparator() + "KU=" + publicKey;
    }
  }
}
