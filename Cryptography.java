import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
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
    Name: SHA1Hash
    Purpose: Hash a byte array using the sha-1 algorithm
    Author: Doctor Burris and Samuel McManus
    Parameter DHBytes: The session key received from the diffie-hellman algorithm
    Return: A hash of the session key
    Uses: N/A
    Used By: Listen
    Date: September 18, 2020
     */
    public static byte[] SHAHash(byte[] DHBytes) throws NoSuchAlgorithmException {
        //Creates an instance of the sha-1 message digest
        MessageDigest Sha = MessageDigest.getInstance("SHA-256");
        //Feeds the input to the Sha algorithm and returns the digest
        Sha.update(DHBytes);
        return Sha.digest();
    }
    /*
    Name: DESKeyGen
    Purpose: Generate a DES key using the session key as the password
    Author: Doctor Burris
    Parameter Parameter: A hash of the session key received from the diffie-hellman algorithm
    Return: The secret DES key
    Uses: N/A
    Used By: DESEncrypt
    Date: September 18, 2020
     */
    public static SecretKey DESKeyGen(byte[] Password) throws InvalidKeyException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        //Create a key specification from the password
        DESKeySpec desKeySpec = new DESKeySpec(Password);
        //Get an instance of the DES algorithm and return the secret key made from it
        SecretKeyFactory KeyFactory = SecretKeyFactory.getInstance("DES");
        return KeyFactory.generateSecret(desKeySpec);
    }
    /*
    Name: BlowfishKeyGen
    Purpose: Generate a Blowfish key spec
    Author: Doctor Burris
    Parameter Password: A hash of the session key received from the diffie-hellman algorithm
    Return: The blowfish secret key spec
    Uses: N/A
    Used By: Connect
    Date: September 22, 2020
    */
    public static SecretKeySpec BlowfishKeyGen(byte[] Password){
        return new SecretKeySpec(Password, "Blowfish");
    }
    /*
    Name: DESedeKeyGen
    Purpose: Generate a 3DES key
    Author: Doctor Burris
    Parameter Password: A hash of the session key received from the diffie-hellman algorithm
    Return: The 3DES key
    Uses: N/A
    Used By: Listen
    Date: September 22, 2020
     */
    public static SecretKey DESedeKeyGen(byte[] Password) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        DESedeKeySpec DESKeySpec = new DESedeKeySpec(Password);
        SecretKeyFactory KeyFactory = SecretKeyFactory.getInstance("DESede");
        return KeyFactory.generateSecret(DESKeySpec);
    }
    /*
       Name: Encrypt
       Purpose: Encrypt a plaintext
       Author: Doctor Burris and Samuel McManus
       Parameter SessionBytes: A hash of the session key
       Parameter Output: The socket used to output data
       Uses: DESKeyGen
       Used By: Listen
       Date: September 21, 2020
        */
    public static void Encrypt(Cipher MyCipher, ObjectOutputStream Output) throws
            IOException, BadPaddingException, IllegalBlockSizeException {
        //Initializes a file input stream
        FileInputStream fin = new FileInputStream("ServerFile.txt");
        //Writes out the initialization vector and the length of the initialization vector
        byte[] iv = MyCipher.getIV();
        Output.writeObject(iv);
        Output.flush();

        System.out.println("\nMy encrypted ciphertext");
        //Writes in 128 byte blocks
        byte[] Input = new byte[128];
        //Infinitely loops reading 128 bytes from the file, encrypting those bytes,
        //and writing them to the output stream
        while(true){
            int BytesRead = fin.read(Input);
            if(BytesRead == -1)
                break;
            byte[] OutputBytes = MyCipher.update(Input, 0, BytesRead);
            if(OutputBytes != null) {
                System.out.print(new String(OutputBytes));
                Output.writeObject(OutputBytes);
            }
        }
        //Write the final bytes to the output stream and close the file.
        byte[] OutputBytes = MyCipher.doFinal();
        if(OutputBytes != null) {
            System.out.println(new String(OutputBytes));
            Output.writeObject(OutputBytes);
        }
        fin.close();
        Output.flush();
        //Because the output will be too long to flush all at once, finish by writing the bytes
        //for the word "finished"
        Output.writeObject("finished".getBytes());
        Output.flush();
    }
    /*
    Name: Decrypt
    Purpose: Decrypt a ciphertext
    Author: Doctor Burris and Samuel McManus
    Parameter SessionBytes: A hash of the session key
    Parameter IV: The initialization vector
    Parameter CipherText: The ciphertext from the user
    Uses: DESKeyGen
    Used By: Connect
    Date: September 21, 2020
     */
    public static void Decrypt(Cipher MyCipher, byte[] CipherText) throws
            BadPaddingException, IllegalBlockSizeException {
        String Plaintext = "";
        //Write the final bytes to the output stream and close the file.
        byte[] OutputBytes = MyCipher.doFinal(CipherText);
        if(OutputBytes != null)
            Plaintext = new String(OutputBytes);
        //Reads out the decrypted plaintext to the terminal
        System.out.println("\nDecrypted plaintext:");
        System.out.println(Plaintext);
    }
}
