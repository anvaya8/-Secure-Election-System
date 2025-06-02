package CLA;

import Keys.RSA;
import Keys.RSA.PrivateKey;
import Keys.RSA.PublicKey;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

public class CLA {

    private static final int PORT = 7777;
    private static final String VALIDATION_FILE = "data/ValidationNumbers.txt";

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("CLA Server started on port " + PORT + "...");

            // Load CLA's private key for decrypting voter IDs
            PrivateKey privateKey = loadPrivateKey("Keys/private_key.txt");
            System.out.println("DEBUG: CLA private key loaded.");

            while (true) {
                try (Socket voter = serverSocket.accept()) {
                    System.out.println("Voter connected");

                    DataInputStream in = new DataInputStream(voter.getInputStream());
                    DataOutputStream out = new DataOutputStream(voter.getOutputStream());

                    // Receive encrypted voter ID
                    int length = in.readInt();
                    byte[] encryptedBytes = new byte[length];
                    in.readFully(encryptedBytes);
                    System.out.println("DEBUG: Received encrypted data (" + length + " bytes)");

                    // Decrypt voter ID using CLA's private key
                    byte[] decryptedBytes;
                    try {
                        decryptedBytes = RSA.cipher(encryptedBytes, privateKey);
                    } catch (Exception e) {
                        System.out.println("Error during RSA decryption: " + e.getMessage());
                        continue;
                    }

                    String voterID = new String(decryptedBytes).trim();
                    System.out.println("DEBUG: Decrypted Voter ID → " + voterID);

                    // Check if voter has already been issued a validation number
                    if (hasVoterAlreadyReceivedValidationNumber(VALIDATION_FILE, voterID)) {
                        System.out.println("Voter has already received a validation number. Blocking repeat vote.");
                        out.writeUTF("You are not allowed to vote again.");
                    } else {
                        // Generate and save a new validation number
                        String validationNumber = generateValidationNumber();
                        saveValidationNumber(VALIDATION_FILE, voterID, validationNumber);
                        System.out.println("Generated validation number: " + validationNumber);

                        // Encrypt validation number with voter's public key and send
                        try {
                            PublicKey voterPublicKey = loadPublicKey("Keys/" + voterID + "_public.txt");
                            byte[] encryptedValidation = RSA.cipher(validationNumber, voterPublicKey);
                            out.writeInt(encryptedValidation.length);
                            out.write(encryptedValidation);
                            System.out.println("DEBUG: Sent encrypted validation to voter.");
                        } catch (Exception e) {
                            System.out.println("Error sending encrypted validation to voter: " + e.getMessage());
                        }

                        // Encrypt validation number with CTF's public key and send
                        try (
                                Socket ctfSocket = new Socket("localhost", 8888);
                                DataOutputStream ctfOut = new DataOutputStream(ctfSocket.getOutputStream())
                        ) {
                            PublicKey ctfPublicKey = loadPublicKey("Keys/ctf_public.txt");
                            byte[] encryptedForCTF = RSA.cipher(validationNumber, ctfPublicKey);

                            ctfOut.writeUTF("CLA_VALIDATION");
                            ctfOut.writeInt(encryptedForCTF.length);
                            ctfOut.write(encryptedForCTF);

                            System.out.println("DEBUG: Sent encrypted validation to CTF.");
                        } catch (IOException e) {
                            System.out.println("Failed to send validation number to CTF: " + e.getMessage());
                        }
                    }

                } catch (Exception e) {
                    System.out.println("Error handling voter connection: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Server failed to start: " + e.getMessage());
        }
    }

    // Load a private key from file (used for decrypting voter ID)
    private static PrivateKey loadPrivateKey(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine().replace("{", "").replace("}", "");
            String[] parts = line.split(",");
            BigInteger d = new BigInteger(parts[0].trim());
            BigInteger n = new BigInteger(parts[1].trim());
            return new PrivateKey(d, n);
        }
    }

    // Load a public key from file (used for encrypting validation numbers)
    private static PublicKey loadPublicKey(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine().replace("{", "").replace("}", "");
            String[] parts = line.split(",");
            BigInteger e = new BigInteger(parts[0].trim());
            BigInteger n = new BigInteger(parts[1].trim());
            return new PublicKey(e, n);
        }
    }

    // Generate random validation number
    private static String generateValidationNumber() {
        Random rand = new Random();
        int number = 10000000 + rand.nextInt(90000000);
        return Integer.toString(number);
    }

    // Save voter ID and validation number to file
    private static void saveValidationNumber(String filename, String voterID, String validNum) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename, true))) {
            writer.write(voterID + "," + validNum);
            writer.newLine();
        } catch (IOException e) {
            System.out.println("Unable to write validation number: " + e.getMessage());
        }
    }

    // Check if voter already received a validation number
    private static boolean hasVoterAlreadyReceivedValidationNumber(String filename, String voterID) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 1 && parts[0].trim().equals(voterID)) {
                    return true;
                }
            }
        } catch (IOException e) {
            System.out.println("Error reading validation file: " + e.getMessage());
        }
        return false;
    }
}
