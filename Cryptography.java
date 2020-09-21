import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Cryptography {
    /*
    Name: GenerateKeys
    Purpose: Generates a set of keys used to create a symmetric key pair with
             Diffie-Hellman
    Author: Doctor Burris
    Return: The public-private key-pair used for Diffie-Hellman
    Uses: N/A
    Used By: DiffieHellman
    Date: September 15, 2020
     */
    public static KeyPair GenerateKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator ServerKPG = KeyPairGenerator.getInstance("DH");
        ServerKPG.initialize(SKIP.sDHParameterSpec);
        return ServerKPG.genKeyPair();
    }
    /*
    Name: DiffieHellman
    Purpose: Create a session key for encryption
    Author: Doctor Burris
    Parameter Input: The client's input
    Parameter Output: Output to the client
    Return: The session key
    Uses: GenerateKeys
    Used By: Listen
    Date: September 16, 2020
     */
    public static byte[] DiffieHellman(ObjectInputStream Input, ObjectOutputStream Output) throws
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException,
            ClassNotFoundException, InvalidKeySpecException, InvalidKeyException {

        //Generate the public-private pair used for diffie-hellman
        KeyPair DHKeys = Cryptography.GenerateKeys();
        //Read in the client's public key as an array of bytes
        byte[] ClientPublicBytes =
                Base64.getDecoder().decode((((String)Input.readObject()).trim()));
        //Create a Diffie-Hellman key factory
        KeyFactory factory = KeyFactory.getInstance("DH");
        //Create an x509 key spec using the byte array of the client's public key
        X509EncodedKeySpec x509Spec =
                new X509EncodedKeySpec(ClientPublicBytes);
        //Generate a public key from the factory using the x509 key specification
        PublicKey ClientPublicKey = factory.generatePublic(x509Spec);
        //Sends the server's public key to the client as a base 64 string
        Output.writeObject(Base64.getEncoder().encodeToString(DHKeys.getPublic().getEncoded())
                + "\n");
        Output.flush();
        //Generate the secret session key
        KeyAgreement SecretKeyAgreement = KeyAgreement.getInstance("DH");
        SecretKeyAgreement.init(DHKeys.getPrivate());
        SecretKeyAgreement.doPhase(ClientPublicKey, true);
        return SecretKeyAgreement.generateSecret();
    }
    /*
    Name: DiffieHellman
    Purpose: Hash a byte array using the sha-1 algorithm
    Author: Doctor Burris and Samuel McManus
    Parameter DHBytes: The session key received from the diffie-hellman algorithm
    Return: A hash of the session key
    Uses: N/A
    Used By: Listen
    Date: September 18, 2020
     */
    public static byte[] SHA1Hash(byte[] DHBytes) throws NoSuchAlgorithmException {
        //Creates an instance of the sha-1 message digest
        MessageDigest Sha = MessageDigest.getInstance("SHA");
        //Feeds the input to the Sha algorithm and returns the digest
        Sha.update(DHBytes);
        return Sha.digest();
    }
    public static SecretKey DESKeyGen(byte[] Password) throws InvalidKeyException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        //Create a key specification from the password
        DESKeySpec desKeySpec = new DESKeySpec(Password);
        //Get an instance of the DES algorithm and return the secret key made from it
        SecretKeyFactory KeyFactory = SecretKeyFactory.getInstance("DES");
        return KeyFactory.generateSecret(desKeySpec);
    }
}
