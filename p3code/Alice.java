
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.net.ServerSocket;
import java.net.Socket;

import java.nio.charset.Charset;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.spec.SecretKeySpec;

//import csec2015
import csec2015.CSec2015Prov;

/**
 * Implements side A of the Oblivious Transfer Protocol.
 */
public class Alice {
    /**
     * Default constructor.
     *
     * @param in an InputStream used to receive messages from Bob.
     * @param out an OutpuStream used to send messages to Bob.
     */
    public Alice(InputStream in, OutputStream out) {
        this.in = new TLVInputStream(in);
        this.out = new TLVOutputStream(out);
    }
    
    /**
     * A default driver for those needing a quick-and-dirty test.
     *
     * This driver opens port 8023 waiting for Bob to connect. Once he does, the
     * OTP is executed once. The result is returned as the process exit code.
     * In the event Bob is caught cheating, the process exit code is -1.
     *
     * You will probably want to write a more capable driver for your own
     * testing.
     */
    public static void main(String[] args) {
        Security.addProvider(new csec2015.CSec2015Prov());
/*        Security.addProvider(
            new org.bouncycastle.jce.provider.BouncyCastleProvider());*/
        int result = -10; // Some result code not used anywhere else
        System.err.print("Alice: Waiting for connection on port 8023: ");
        try {
            ServerSocket s = new ServerSocket(8023);
            Socket c = s.accept();
            System.err.println(" Connected.");
            
            Alice sideA = new Alice(c.getInputStream(), c.getOutputStream());
            result = sideA.execute();
        } catch (OTPCheatException e) {
            e.printStackTrace();
            System.err.println("\nCheating Detected: " + e);
            System.exit(-1);
        } catch (java.io.IOException e) {
            e.printStackTrace();
            System.err.println("\nError opening socket: " + e);
            System.exit(-2);
        } catch (OTPException e) {
            e.printStackTrace();
            System.err.println("\nError executing OTP: " + e);
            System.exit(-3);
        } catch (TLVException e) {
            e.printStackTrace();
            System.err.println("\nCommunication error executing OTP: " + e);
            System.err.println("This typically occurs when Bob disconnects," +
                               " crashes, or sends a message out of order.");
            System.exit(-4);
        }
        switch (result) {
            case Outcome.LOSE: {
                System.out.println("Alice: I Lose");
            } break;
            case Outcome.WIN: {
                System.out.println("Alice: I Win");
            } break;
            default: {
                // This should never happen
                System.err.println("Internal Error");
            }
        }
        System.exit(result);
    }
    
    /**
     * Execute side A of the Oblivious Transfer Protocol.
     *
     * Executes the OTP using the provided communication channels.
     * @return the outcome of the OTP: Outcome.WIN or Outcome.LOSE.
     */
    int execute() throws OTPException {
        // Instantiate a commutative RSA key pair generator for 2048-bit keys
        KeyPairGenerator comm_gen = null;
        try {
            comm_gen = KeyPairGenerator.getInstance("RSACommutative", "CSec2015");
            comm_gen.initialize(2048);
        } catch (NoSuchAlgorithmException e) {
            throw new OTPException("Commutative RSA generator not available",
                                   e);
        } catch (NoSuchProviderException e) {
            throw new OTPException("CSec2015 Provider is not available", e);
        } catch (InvalidParameterException e) {
            throw new OTPException("Cannot generate appropriately-sized keys",
                                   e);
        }
        
        // Instantiate a charmap for encoding strings later
        Charset utf8 = Charset.forName("UTF-8");
        
        // Step 1: Generate two asymmetric key pairs.
        System.err.println("Alice: Step 1");
        KeyPair K_I = comm_gen.generateKeyPair();
        KeyPair K_J = comm_gen.generateKeyPair();
        
        System.err.println("Alice: Step 1 Executed");

        // Step 2: Performed only by Bob.
        System.err.println("Alice: Step 2 Performed by Bob");

        // Step 3: Send Bob the public keys.
        System.err.println("Alice: Step 3");
        try {
            out.put(0x30, K_I.getPublic().getEncoded()); //X.509 Encoding
            out.put(0x31, K_J.getPublic().getEncoded()); //X.509 Encoding
        } catch (IOException e) {
            throw new OTPException("Unable to send public keys", e);
        }
        
        System.err.println("Alice: Step 3 Executed");

        // Step 4: Receive encrypted K_B (Bob's sym key 0x40)
        System.err.println("Alice: Step 4");
        byte[] K_B_H_data = null;
        try {
            K_B_H_data = in.get(0x40);
        } catch (IOException e) {
            throw new OTPException("Unable to receive encrypted key", e);
        }
        
        System.err.println("Alice: Step 4 Executed");

        // Step 5: Select G (is the coin heads or tails?),and decrypt K_B.
        System.err.println("Alice: Step 5");
        byte G = (byte)(new BigInteger(1, random).intValue());
        KeyPair K_G = G == 0 ? K_I : K_J;
        Key K_A = null;
        try {
            K_A = Common.decryptKey((RSAPrivateKey)K_G.getPrivate(),
                                    K_B_H_data);
        } catch (IllegalBlockSizeException e) {
            throw new OTPCheatException("Bob sent a corrupt key", e);
        } catch (InvalidKeyException e) {
            throw new OTPCheatException("Bob sent a corrupt key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new OTPException("AES algorithm not available", e);
        } catch (BadPaddingException e) {
            throw new OTPCheatException("Bob sent a corrupt key", e);
        } catch (NoSuchPaddingException e) {
            throw new OTPException("NoPadding not available for RSA", e);
        }
        
        System.err.println("Alice: Step 5 Executed");

        // Step 6: Send the encrypted message.
        System.err.println("Alice: Step 6");
        Cipher K_A_cipher = null;
        try {
            K_A_cipher = Cipher.getInstance("AES/ECB/NoPadding");
            K_A_cipher.init(Cipher.ENCRYPT_MODE, K_A);
            out.put(0x60, K_A_cipher.doFinal(Msg.getBytes(utf8)));
        } catch (NoSuchAlgorithmException e) {
            throw new OTPException("AES not available", e);
        } catch (NoSuchPaddingException e) {
            throw new OTPException("NoPadding not available for AES", e);
        } catch (InvalidKeyException e) {
            throw new OTPCheatException("Bob provided an invalid AES key", e);
        } catch (IllegalBlockSizeException e) {
            throw new OTPException("Message must be 16*n bytes in length", e);
        } catch (BadPaddingException e) {
            // Should not be an issue in encrypt mode
            throw new OTPException("Internal error", e);
        } catch (IOException e) {
            throw new OTPException("Unable to send encrypted message", e);
        }
        try {
            out.putByte(0x61, G);
        } catch (IOException e) {
            throw new OTPException("Unable to send coin flip result", e);
        }
        
        System.err.println("Alice: Step 6 Executed");

        // Step 7: Receive the decrypted message and H (what did Bob call?)
        System.err.println("Alice: Step 7");
        String M = null;
        try {
            M = new String(in.get(0x70), utf8);
        } catch (IOException e) {
            throw new OTPException("Unable to receive decrypted message", e);
        }
        byte H = 0;
        try {
            H = in.getByte(0x71);
        } catch (IOException e) {
            throw new OTPException("Unable to receive Bob's call", e);
        }
        
        System.err.println("Alice: Step 7 Executed");

        // Step 8: Send Bob the private keys
        System.err.println("Alice: Step 8");
        try {
            out.put(0x80, K_I.getPrivate().getEncoded()); //PKCS8 Encoding
            out.put(0x81, K_J.getPrivate().getEncoded()); //PKCS8 Encoding
        } catch (IOException e) {
            throw new OTPException("Unable to send private keys");
        }
        
        // Interpret the result
        if (G == H) {
            if (M.equals(Msg)) {
                return Outcome.LOSE;
            } else {
                throw new OTPCheatException(
                    "Bob claims he called correctly, but he failed to decrypt" +
                    " the message.");
            }
        } else {
            if (M.equals(Msg)) {
                throw new OTPCheatException(
                    "Bob seems to have the correct message, but his call is" +
                    " wrong.");
            } else {
                return Outcome.WIN;
            }
        }
    }
    
    private String Msg = "I lose. ~Alice:("; //length must be a multiple of 16
    private TLVInputStream in;
    private TLVOutputStream out;
    private SecureRandom random = new SecureRandom();
}
