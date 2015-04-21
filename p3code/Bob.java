
import java.math.BigInteger;

import java.nio.charset.Charset;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
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
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

//import csec2015
import csec2015.CSec2015Prov;

/**
 * Implements side B of the Oblivious Transfer Protocol.
 */
public class Bob {
    
    private TLVInputStream in;
    private TLVOutputStream out;
    private SecureRandom secureRandom = new SecureRandom();
    
    /**
     * Default constructor.
     *
     * @param in an InputStream used to receive messages from Alice.
     * @param out an OutpuStream used to send messages to Alice.
     */
    public Bob(InputStream in, OutputStream out) {
        this.in = new TLVInputStream(in);
        this.out = new TLVOutputStream(out);
    }
    
    public static void main(String[] args) {
        Security.addProvider(new csec2015.CSec2015Prov());  //Import included security classes
        int result = -10; // Some result code not used anywhere else
        System.err.print("Bob waiting for connection on port 8023: ");
        
        try {
            //Use loopback IP Address to find address for Socket Alice created
        	InetAddress address = InetAddress.getByName("127.0.0.1"); 
        	//Creates new socket
            Socket c = new Socket(address, 8023);
            //Creates input and output for Bob
            Bob sideB = new Bob(c.getInputStream(), c.getOutputStream());
            //Execs Bob's OTP
            result = sideB.execute();
            
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
            System.err.println("This typically occurs when Bob disconnects," + " crashes, or sends a message out of order.");
            System.exit(-4);
        }
        switch (result) {  //Switch statement to output results of OTP
            case Outcome.LOSE: {
                System.out.println("Bob: I Lose");
            } break;
            case Outcome.WIN: {
                System.out.println("Bob: I Win");
            } break;
            default: {
                // This should never happen
                System.err.println("Internal Error");
            }
        }
        System.exit(result);
    }
    
    /**
     * Execute side B of the Oblivious Transfer Protocol.
     *
     * Executes the OTP using the provided communication channels.
     * @return the outcome of the OTP: Outcome.WIN or Outcome.LOSE.
     */
    int execute() throws OTPException {
        // Instantiate a charmap for encoding strings later
    	Charset utf8 = Charset.forName("UTF-8");
    	
    	//Step 1: Performed only by Alice.
        System.err.println();
        System.err.println("Bob: Step 1 Performed by Alice");
    	
    	
    	//Step 2: Generates symmetric key K_B.
    	System.err.println("Bob: Step 2 ");
    	
        //byte array for K_B
		byte[] kBArray = new byte[16];
        //Fill array with random bytes
		secureRandom.nextBytes(kBArray);
    	
        //AES key for K_B
    	SecretKeySpec K_B = new SecretKeySpec(kBArray, "AES");

     	System.err.println("Bob: Step 2 Executed");
    	 
     	//Step 3: Receives K_I_public and K_J_public. (Messages 0x30, 0x31)
    	System.err.println("Bob: Step 3 ");
    	
        //encoded keys
    	X509EncodedKeySpec K_I_public_encoded;
    	X509EncodedKeySpec K_J_public_encoded;

		try {

            //stores encoded K_I and K_J public
			K_I_public_encoded = new X509EncodedKeySpec(in.get(0x30));
			K_J_public_encoded = new X509EncodedKeySpec(in.get(0x31));
		} catch (IOException e) {
            throw new OTPException("Unable to get encrypted message with K_I or K_J", e);
		} catch (TLVException e) {
			throw new OTPException("Unable to get encrypted message with K_I or K_J (Problem with TLV)", e);
		}
		
        //Store decoded version of K_I and K_J public
		PublicKey K_I_public;
		PublicKey K_J_public;
		
		try {
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
            //Decode K_I and K_J public
			K_I_public = keyfactory.generatePublic(K_I_public_encoded);
			K_J_public = keyfactory.generatePublic(K_J_public_encoded);
		} catch (NoSuchAlgorithmException e) {
			throw new OTPException("RSA not available", e);
		} catch (InvalidKeySpecException e) {
			throw new OTPCheatException("K_I or K_J encoding cannot be deciphered", e);
		}
		
     	System.err.println("Bob: Step 3 Executed");
    	
     	//Step 4: Selects K_H from K_I_public and K_J_public at random and sends K_B encrypted by K_H to Alice. (Message 0x40)
    	System.err.println("Bob: Step 4 ");
    	
        //H random byte==0 or byte==1
    	byte H = (byte)(new BigInteger(1, secureRandom).intValue());
    	
        //Store K_H public
        PublicKey K_H;

        if (H==0) {
            //Sets K_H to K_J_public if H==0
    		K_H = K_I_public;
    	}
        else {
            //Sets K_H to K_J_public if H==1
        	K_H = K_J_public;
        }
        //Creates byte array to store encrypted K_B with K_H
        byte[] KB_KH_data = null;
        
        try {
            //Encrypts K_B with K_H 
			KB_KH_data = Common.encryptKey((RSAPublicKey) K_H, K_B, secureRandom);
		} catch (InvalidKeyException e) {
            throw new OTPCheatException("Invalid RSA key given", e);
		} catch (NoSuchAlgorithmException e) {
			throw new OTPException("RSA not available", e);
		} catch (IllegalBlockSizeException e) {
            throw new OTPCheatException("RSA key given has incorrect block size", e);
		} catch (BadPaddingException e) {
			throw new OTPCheatException("RSA key given has bad padding", e);
		} catch (NoSuchPaddingException e) {
			throw new OTPException("NoPadding not available for RSA", e);
		}
        
        try {
            //Send K_B encrypted with K_H_public as a byte array to Alice
			out.put(0x40, KB_KH_data);
		} catch (IOException e) {
			throw new OTPException("Unable to send encrypted message with K_B_H", e);
		}
        
     	System.err.println("Bob: Step 4 Executed");
    	
     	//Step 5: Performed only by Alice.
    	System.err.println("Bob: Step 5 performed by Alice");
    	
     	//Step 6: Receive encrypted message from Alice. (Messages 0x60, 0x61)
    	System.err.println("Bob: Step 6 ");
    	
    	byte[] msg_KA;
    	byte G;
    	
    	try {
            //Receive encrypted message from Alice
			msg_KA = in.get(0x60);
            //Receive the result of the coin flip from ALice
			G = in.getByte(0x61);
		} catch (TLVException e) {
			throw new OTPException("Unable to get encrypted message K_A or byte G (Problem with TLV)", e);
		} catch (IOException e) {
			throw new OTPException("Unable to get encrypted message K_A or byte G", e);
		}
    	
     	System.err.println("Bob: Step 6 Executed");
    	
     	//Step 7: Decrypts message M from Alice and sends M and H to Alice. (Messages 0x70, 0x71)
    	System.err.println("Bob: Step 7 ");
    	
    	Cipher K_M_cipher = null;
    	byte[] message;
    	 try {
            //Sets up cipher
             K_M_cipher = Cipher.getInstance("AES/ECB/NoPadding");
            //Sets cipher to decrypt with K_B
             K_M_cipher.init(Cipher.DECRYPT_MODE, K_B);
            //Tries decrypting the msg_KA with K_B; wins if successful
             message = K_M_cipher.doFinal(msg_KA);
         } catch (NoSuchAlgorithmException e) {
             throw new OTPException("AES not available", e);
         } catch (NoSuchPaddingException e) {
             throw new OTPException("NoPadding not available for AES", e);
         } catch (InvalidKeyException e) {
             throw new OTPCheatException("Invalid AES key given", e);
         } catch (IllegalBlockSizeException e) {
             throw new OTPException("Message must be 16*n bytes in length", e);
		} catch (BadPaddingException e) {
            throw new OTPException("Internal error", e);
		}
    	
         try {
            //Send Alice decrypted message
             out.put(0x70, message);
            //Sends Bob's call (H)
             out.putByte(0x71, H);
         } catch (IOException e) {
             throw new OTPException("Unable to send message or byte H", e);
         }
    	
      	System.err.println("Bob: Step 7 Executed");
         
      	//Step 8: Receives K_I_private and K_J_private for verification purposes. (Messages 0x80, 0x81)
    	System.err.println("Bob: Step 8 ");
    	
        //Store encoded K_I and K_J privates
    	PKCS8EncodedKeySpec K_I_private_encoded;
    	PKCS8EncodedKeySpec K_J_private_encoded;

    	try {
            //Receive encoded K_I and K_J private to verify
			K_I_private_encoded = new PKCS8EncodedKeySpec(in.get(0x80));
	    	K_J_private_encoded = new PKCS8EncodedKeySpec(in.get(0x81));
		} catch (TLVException e) {
			throw new OTPException("Unable to get  K_I_private_encoded or K_J_private_encoded (Problem with TLV)", e);
		} catch (IOException e) {
			throw new OTPException("Unable to get  K_I_private_encoded or K_J_private_encoded", e);
		}
    	
        //Store decoded K_I and K_J privates
		PrivateKey K_I_private;
		PrivateKey K_J_private;
    	
		try {
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
            //Decode K_I and K_J private
			K_I_private = keyfactory.generatePrivate(K_I_private_encoded);
			K_J_private = keyfactory.generatePrivate(K_J_private_encoded);
		} catch (NoSuchAlgorithmException e) {
			throw new OTPException("RSA not available", e);
		} catch (InvalidKeySpecException e) {
			throw new OTPCheatException("K_I_private or K_J_private encoding cannot be deciphered", e);
		}
		
     	System.err.println("Bob: Step 8 Executed");
		
     	// Interpret the result
		
        if (H == G) {
			return Outcome.WIN;
		}
		else {
			try {
				if (!(K_B.equals((Common.decryptKey((RSAPrivateKey)K_I_private, KB_KH_data))) || (K_B.equals((Common.decryptKey((RSAPrivateKey)K_J_private, KB_KH_data)))))) {  //Test K_I_private and K_J_private for validity by trying do decrypt KB_KH_data from step 4
					throw new OTPCheatException("Bob: Neither K_I_public or K_J_public provided could decrypt {K_B}K_H_public");
				}
				
				else if (K_I_public.equals(K_J_public)) {
					throw new OTPCheatException("Bob: Both K_I_public and K_J_public are the same");
				}
				
				else if (K_I_private.equals(K_J_private)) {
					throw new OTPCheatException("Bob: Both K_I_private and K_J_private are the same");
				}
				
				else if (K_I_private.equals(K_I_public)) {
					throw new OTPCheatException("Bob: Both K_I_private and K_I_public are the same");
				}
				
				else if (K_J_private.equals(K_J_public)) {
					throw new OTPCheatException("Bob: Both K_J_private and K_J_public are the same");
				} 
				else {
					return Outcome.LOSE;
				}
			} catch (InvalidKeyException |IllegalBlockSizeException | BadPaddingException e) {
				throw new OTPException("Key during check of K_I and K_J");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				throw new OTPException("Method error during check of K_I and K_J");
			}
		}
    }

}
