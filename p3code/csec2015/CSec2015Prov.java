
package csec2015;

import java.security.Provider;

/**
 * A Provider that links the commutative RSA key pair generator into the JCE
 */
public class CSec2015Prov extends Provider {
    /**
     * Constructor.
     *
     * Use this with java.security.Security.addProvider() to install this
     * provider into your programs.
     *
     * Note: this is only useful if your program needs to generate commutative
     * key pairs. It provides no other services. If you are only encrypting and
     * decrypting (even with given commutative keys) you do not need this
     * provider.
     */
    public CSec2015Prov() {
        super("CSec2015", 1.0, "Provider for Alice's commutative RSA generator.");
        put("KeyPairGenerator.RSACommutative",
            "csec2015.CommutativeRSAKeyPairGenerator");
    }
}
