package Voter;

import Keys.RSA;
import Keys.RSA.PublicKey;
import Keys.RSA.PrivateKey;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Scanner;

public class Voter {

    private static String voterID;
    private static String password;
    private static final int CLA_PORT = 7777;
    private static final int CTF_PORT = 8888;
    private static final String CLA_HOST = "localhost";
    private static final String CTF_HOST = "localhost";
    private static String validationNumber;

    private static boolean alreadyVoted = false;
    private static boolean hasAttemptedValidation = false;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean loggedIn = false;

        System.out.println("Welcome to the Secure Election Portal!");

        while (true) {
            System.out.println("\nMain Menu:");
            System.out.println("1. Login");
            System.out.println("2. Exit");
            System.out.print("Select an option: ");
            int choice = Integer.parseInt(scanner.nextLine().trim());

            if (choice == 1) {
                loggedIn = login(scanner);
                if (loggedIn) {
                    while (true) {
                        System.out.println("\nElection Menu:");
                        System.out.println("1. Get Validation Number");
                        System.out.println("2. Vote for a Candidate");
                        System.out.println("3. View Results");
                        System.out.println("4. Logout");
                        System.out.print("Your choice: ");
                        int subChoice = Integer.parseInt(scanner.nextLine().trim());

                        switch (subChoice) {
                            case 1:
                                validationNumber = getValidationNumber();
                                System.out.println("DEBUG: validationNumber now holds → " + validationNumber);
                                if (validationNumber == null) {
                                    if (alreadyVoted) {
                                        System.out.println("You have already cast your vote. You may view the results.");
                                    } else {
                                        System.out.println("Unable to assign validation number.");
                                    }
                                }
                                break;

                            case 2:
                                if (alreadyVoted) {
                                    System.out.println("You have already cast your vote. You may view the results.");
                                } else if (validationNumber == null) {
                                    if (hasAttemptedValidation) {
                                        System.out.println("You were denied a validation number. Voting not allowed.");
                                    } else {
                                        System.out.println("You must obtain a validation number before voting.");
                                    }
                                } else {
                                    castVote(scanner, validationNumber);
                                }
                                break;

                            case 3:
                                showResults();
                                break;

                            case 4:
                                System.out.println("Logging out. Thank you for participating.");
                                return;

                            default:
                                System.out.println("Invalid input. Try again.");
                        }
                    }
                }
            } else if (choice == 2) {
                System.out.println("Exiting the system. Have a nice day!");
                break;
            } else {
                System.out.println("Invalid input. Please select from the menu.");
            }
        }
    }

    // Login and verify voter credentials from file
    private static boolean login(Scanner scanner) {
        System.out.print("Enter your Voter ID: ");
        voterID = scanner.nextLine().trim();
        System.out.print("Enter your Password: ");
        password = scanner.nextLine().trim();

        try (
                BufferedReader idReader = new BufferedReader(new FileReader("data/VoterID.txt"));
                BufferedReader pwReader = new BufferedReader(new FileReader("data/VoterPassword.txt"))
        ) {
            String idLine, pwLine;
            while ((idLine = idReader.readLine()) != null && (pwLine = pwReader.readLine()) != null) {
                if (voterID.equals(idLine.trim()) && password.equals(pwLine.trim())) {
                    System.out.println("Attempting to connect to CTF at port " + CTF_PORT + "...");
                    System.out.println("Connection established with CTF.");
                    System.out.println("Login successful!");
                    alreadyVoted = checkIfVoterHasAlreadyVoted(voterID);
                    if (alreadyVoted) {
                        System.out.println("NOTE: Our records show that you have already voted.");
                    }
                    return true;
                }
            }
            System.out.println("Login failed. Please check your credentials.");
        } catch (IOException e) {
            System.out.println("Login error: " + e.getMessage());
        }
        return false;
    }

    // Securely request and decrypt the validation number from CLA
    private static String getValidationNumber() {
        try (
                Socket socket = new Socket(CLA_HOST, CLA_PORT);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())
        ) {
            System.out.println("Connecting to CLA on port " + CLA_PORT + "...");

            // Encrypt voter ID with CLA's public key
            PublicKey claPublicKey = loadPublicKey("Keys/public_key.txt");
            byte[] encryptedVoterID = RSA.cipher(voterID, claPublicKey);
            out.writeInt(encryptedVoterID.length);
            out.write(encryptedVoterID);
            System.out.println("DEBUG: Voter ID encrypted and sent to CLA.");

            hasAttemptedValidation = true;

            // Receive encrypted validation number from CLA
            int len = in.readInt();
            byte[] encryptedResponse = new byte[len];
            in.readFully(encryptedResponse);
            System.out.println("DEBUG: Encrypted validation number received from CLA.");

            // Load voter's private key to decrypt the validation number
            PrivateKey myPrivateKey = loadPrivateKey("Keys/" + voterID + "_private.txt");
            byte[] decryptedBytes = RSA.cipher(encryptedResponse, myPrivateKey);
            String response = new String(decryptedBytes).trim();
            System.out.println("DEBUG: Decrypted validation number → " + response);

            if (response != null && response.matches("\\d+")) {
                System.out.println("Your validation number is: " + response);
                return response;
            } else {
                if (response.toLowerCase().contains("not allowed")) alreadyVoted = true;
                System.out.println(response);
                return null;
            }

        } catch (Exception e) {
            System.out.println("Failed to contact CLA: " + e.getMessage());
            return null;
        }
    }

    // Send encrypted vote to CTF
    private static void castVote(Scanner scanner, String validationNumber) {
        try (
                Socket socket = new Socket(CTF_HOST, CTF_PORT);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())
        ) {
            System.out.println("Connecting to CTF on port " + CTF_PORT + "...");
            PublicKey ctfPublicKey = loadPublicKey("Keys/public_key.txt");
            out.writeUTF("ENCRYPTED");

            // Encrypt the validation number with CTF's public key
            byte[] encryptedValidation = RSA.cipher(validationNumber, ctfPublicKey);
            out.writeInt(encryptedValidation.length);
            out.write(encryptedValidation);
            System.out.println("DEBUG: Encrypted validation number sent to CTF.");

            String candidateList = in.readUTF();
            if (candidateList.contains("Vote denied")) {
                System.out.println(candidateList);
                return;
            }

            String votePrompt = in.readUTF();
            System.out.println("List of Candidates:");
            System.out.println(candidateList);
            System.out.println(votePrompt);

            System.out.print("Enter your vote (number): ");
            String vote = scanner.nextLine().trim();
            out.writeUTF(vote);

            String confirmation = in.readUTF();
            System.out.println("Vote recorded successfully for: " + confirmation);

        } catch (IOException e) {
            System.out.println("Failed to vote: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Encryption error: " + e.getMessage());
        }
    }

    // Request vote results from CTF
    private static void showResults() {
        try (
                Socket socket = new Socket(CTF_HOST, CTF_PORT);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())
        ) {
            System.out.println("Requesting results from CTF (port " + CTF_PORT + ")...");
            out.writeUTF("RESULT_REQUEST");
            String result = in.readUTF();
            System.out.println("\n--- Current Vote Tally ---");
            System.out.println(result);
        } catch (IOException e) {
            System.out.println("Could not retrieve results: " + e.getMessage());
        }
    }

    // Check if this voter's validation number was already used
    private static boolean checkIfVoterHasAlreadyVoted(String voterId) {
        try (
                BufferedReader reader = new BufferedReader(new FileReader("data/ValidationNumbers.txt"));
                BufferedReader usedReader = new BufferedReader(new FileReader("data/UsedValidationNumbers.txt"))
        ) {
            String validationNumber = null;
            String line;

            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts[0].trim().equals(voterId)) {
                    validationNumber = parts[1].trim();
                    break;
                }
            }

            if (validationNumber != null) {
                while ((line = usedReader.readLine()) != null) {
                    if (line.trim().equals(validationNumber)) return true;
                }
            }

        } catch (IOException e) {
            System.out.println("Warning: Could not check previous voting status: " + e.getMessage());
        }
        return false;
    }

    // Load a public key from file
    private static PublicKey loadPublicKey(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine().replace("{", "").replace("}", "");
            String[] parts = line.split(",");
            BigInteger e = new BigInteger(parts[0].trim());
            BigInteger n = new BigInteger(parts[1].trim());
            return new PublicKey(e, n);
        }
    }

    // Load a private key from file
    private static PrivateKey loadPrivateKey(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine().replace("{", "").replace("}", "");
            String[] parts = line.split(",");
            BigInteger d = new BigInteger(parts[0].trim());
            BigInteger n = new BigInteger(parts[1].trim());
            return new PrivateKey(d, n);
        }
    }
}
