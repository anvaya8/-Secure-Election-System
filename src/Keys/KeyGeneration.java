package Keys;

import Keys.RSA;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

public class KeyGeneration {
  public static void main(String[] args) {
    // List of voter IDs
    String[] voterIDs = {"alice123", "bob456", "charlie789", "anvaya", "kevin", "alma"};

    // Set bit length and certainty for primes
    int bitLength = 256;
    int certainty = 5;

    for (String voterID : voterIDs) {
      // Generate two random primes
      BigInteger p = new BigInteger(bitLength, certainty, new Random());
      BigInteger q = new BigInteger(bitLength, certainty, new Random());

      // Generate key pair
      RSA.KeyPair keyPair = RSA.generateKeys(p, q);
      RSA.PrivateKey privateKey = keyPair.getPrivateKey();
      RSA.PublicKey publicKey = keyPair.getPublicKey();

      // Save to voter-specific files
      saveKeyToFile("Keys/" + voterID + "_private.txt", privateKey);
      saveKeyToFile("Keys/" + voterID + "_public.txt", publicKey);


      System.out.println("Generated keys for " + voterID);
    }

    // Optionally, also generate system-wide CLA/CTF keys
    BigInteger p = new BigInteger(bitLength, certainty, new Random());
    BigInteger q = new BigInteger(bitLength, certainty, new Random());

    RSA.KeyPair systemKeyPair = RSA.generateKeys(p, q);
    saveKeyToFile("Keys/private_key.txt", systemKeyPair.getPrivateKey());
    saveKeyToFile("Keys/public_key.txt", systemKeyPair.getPublicKey());
    saveKeyToFile("Keys/ctf_public.txt", systemKeyPair.getPublicKey());
    System.out.println("Generated system-wide CLA/CTF key pair.");
  }

  private static void saveKeyToFile(String filename, RSA.Key key) {
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
      writer.write(key.toString());
    } catch (IOException e) {
      System.out.println("Error saving key to file: " + e.getMessage());
    }
  }
}
