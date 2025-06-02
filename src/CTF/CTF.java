package CTF;

import Keys.RSA;
import Keys.RSA.PrivateKey;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

public class CTF {

    private static final int PORT = 8888;
    private static final String VALIDATION_FILE = "data/UsedValidationNumbers.txt";
    private static final String TALLY_FILE = "data/VoteTally.txt";

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("CTF Server started on port " + PORT + "...");

            // Load CTF's private key for decryption
            PrivateKey privateKey = loadPrivateKey("Keys/private_key.txt");
            System.out.println("DEBUG: CTF private key loaded.");

            while (true) {
                try (
                        Socket voter = serverSocket.accept();
                        DataInputStream in = new DataInputStream(voter.getInputStream());
                        DataOutputStream out = new DataOutputStream(voter.getOutputStream())
                ) {
                    System.out.println("Voter connected");

                    // Read the first message to determine the type of request
                    String type = in.readUTF();

                    // Handle validation number forwarded by CLA
                    if ("CLA_VALIDATION".equals(type)) {
                        // Read encrypted validation number as byte array
                        int len = in.readInt();
                        byte[] encrypted = new byte[len];
                        in.readFully(encrypted);
                        System.out.println("DEBUG: Received encrypted validation number from CLA.");

                        // Decrypt using CTF's private key
                        byte[] decrypted;
                        try {
                            decrypted = RSA.cipher(encrypted, privateKey);
                        } catch (Exception e) {
                            System.out.println("Error during decryption from CLA: " + e.getMessage());
                            continue;
                        }

                        String validationFromCLA = new String(decrypted).trim();
                        System.out.println("DEBUG: Decrypted validation from CLA → " + validationFromCLA);

                        // Store the validation number to track valid votes
                        appendToFile("data/ValidValidationNumbers.txt", validationFromCLA);
                        continue;
                    }

                    // Return election results if requested by a voter
                    if ("RESULT_REQUEST".equals(type)) {
                        System.out.println("DEBUG: Received result request from voter.");
                        String[] candidates = readVoteTally(TALLY_FILE);
                        StringBuilder results = new StringBuilder("-------- Election Results --------\n");
                        for (String candidate : candidates) {
                            results.append(candidate).append("\n");
                        }
                        out.writeUTF(results.toString());
                        continue;
                    }

                    // Reject invalid message types
                    if (!"ENCRYPTED".equals(type)) {
                        System.out.println("Invalid message type received. Ignoring.");
                        continue;
                    }

                    // Handle encrypted vote from a voter
                    int length = in.readInt();
                    byte[] encryptedBytes = new byte[length];
                    in.readFully(encryptedBytes);
                    System.out.println("DEBUG: Received encrypted validation number.");

                    // Decrypt the validation number submitted with the vote
                    byte[] decryptedBytes;
                    try {
                        decryptedBytes = RSA.cipher(encryptedBytes, privateKey);
                    } catch (Exception e) {
                        System.out.println("Error during RSA decryption: " + e.getMessage());
                        continue;
                    }

                    String validationNumber = new String(decryptedBytes).trim();
                    System.out.println("DEBUG: Decrypted validation number → " + validationNumber);

                    // New method to check if the number is valid
                    if (!isValidValidationNumber(validationNumber)) {
                        out.writeUTF("Invalid or tampered validation number. Vote denied.");
                        continue;
                    }

                    // Check if the validation number was already used
                    if (hasAlreadyVoted(VALIDATION_FILE, validationNumber)) {
                        out.writeUTF("You have already voted. Vote denied.");
                        continue;
                    }

                    // Read current vote tallies
                    String[] candidates = readVoteTally(TALLY_FILE);
                    int[] voteCounts = new int[candidates.length];

                    // Display the current race
                    StringBuilder raceResults = new StringBuilder("-------- Election Race --------\n");
                    for (int i = 0; i < candidates.length; i++) {
                        String[] parts = candidates[i].split(",");
                        raceResults.append(parts[0])
                                .append(" - Total Votes: ")
                                .append(parts[1])
                                .append("\n");
                        voteCounts[i] = Integer.parseInt(parts[1]);
                    }
                    out.writeUTF(raceResults.toString());

                    // Ask voter to choose candidate
                    String votePrompt = "1. Person 1\n2. Person 2\nPlease vote by sending 1 or 2\n";
                    out.writeUTF(votePrompt);

                    // Receive vote response
                    String response = in.readUTF();
                    int voteIndex = response.equals("1") ? 0 : 1;
                    voteCounts[voteIndex]++;
                    String votedCandidateName = candidates[voteIndex].split(",")[0].trim();
                    out.writeUTF(votedCandidateName);

                    // Update tally and mark validation number as used
                    saveVoteTally(TALLY_FILE, candidates, voteCounts);
                    appendToFile(VALIDATION_FILE, validationNumber);
                    System.out.println("DEBUG: Vote recorded for " + votedCandidateName);

                } catch (IOException e) {
                    System.out.println("Error handling voter: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Failed to start CTF server: " + e.getMessage());
        }
    }

    // Load private key from file
    private static PrivateKey loadPrivateKey(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine().replace("{", "").replace("}", "");
            String[] parts = line.split(",");
            BigInteger d = new BigInteger(parts[0].trim());
            BigInteger n = new BigInteger(parts[1].trim());
            return new PrivateKey(d, n);
        }
    }

    // Check if validation number was already used
    private static boolean hasAlreadyVoted(String fileName, String validationNumber) {
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().equals(validationNumber.trim())) {
                    return true;
                }
            }
        } catch (IOException e) {
            System.out.println("Error reading validation file: " + e.getMessage());
        }
        return false;
    }

    // Read current vote tally file
    private static String[] readVoteTally(String fileName) {
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            return reader.lines().toArray(String[]::new);
        } catch (IOException e) {
            System.out.println("Error reading vote tally: " + e.getMessage());
        }
        return new String[]{"Person 1,0", "Person 2,0"};
    }

    // Save updated vote tally
    private static void saveVoteTally(String fileName, String[] candidateNames, int[] voteCounts) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName))) {
            for (int i = 0; i < candidateNames.length; i++) {
                String[] parts = candidateNames[i].split(",")[0].split("\n");
                writer.write(parts[0] + "," + voteCounts[i]);
                writer.newLine();
            }
        } catch (IOException e) {
            System.out.println("Error writing vote tally: " + e.getMessage());
        }
    }

    // Append validation number to used list
    private static void appendToFile(String fileName, String data) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName, true))) {
            writer.write(data);
            writer.newLine();
        } catch (IOException e) {
            System.out.println("Error saving validation number: " + e.getMessage());
        }
    }
    // Check if a validation number was officially issued by CLA and received by CTF
    private static boolean isValidValidationNumber(String validationNumber) {
        try (BufferedReader reader = new BufferedReader(new FileReader("data/ValidValidationNumbers.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().equals(validationNumber.trim())) {
                    return true;
                }
            }
        } catch (IOException e) {
            System.out.println("Error reading valid validation numbers: " + e.getMessage());
        }
        return false;
    }

}
