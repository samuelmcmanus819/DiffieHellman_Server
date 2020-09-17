import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class Verification {
    /*
    Name: Register
    Purpose: Registers a new user
    Author: Samuel McManus
    Return: Whether the registration was successful or not
    Uses: SearchForUser
    Used By: Listen
    Date: September 15, 2020
     */
    static boolean Register(String Username, String Password) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        //If the username already exists, return false
        if(IO.SearchForUser(Username))
            return false;
        //Otherwise insert the user into the file
        else {
            //First compute a salt
            byte[] Salt = CreateSalt();
            //Hash the password with the computed salt.
            String PasswordHash = HashPassword(Password, Salt);
            IO.WriteNewUser(Username, PasswordHash, new String(Salt));
            return true;
        }
    }
    static boolean Login(String Username, String Password) throws IOException {
        String[] UserCreds = IO.GetUser(Username);
        if(UserCreds[0].equals("")){
            return false;
        }
        else{
            System.out.println("a");
            return true;
        }
    }
    /*
    Name: HashPassword
    Parameter Password: The user's plaintext password
    Purpose: Hashes the user's password
    Author: Samuel McManus
    Uses: CreateSalt, BytesToHex
    Used By: Main
    Date: September 14, 2020
     */
    static String HashPassword(String Password, byte[]Salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int Iterations = 9001;

        //Creates a password-based encryption key specification
        PBEKeySpec Spec = new PBEKeySpec(Password.toCharArray(), Salt, Iterations, 512);
        //Creates a key factory object to generate a secret key
        SecretKeyFactory Factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        //Gets an encoded secret key from the factory as a hash
        byte[] HashBytes = Factory.generateSecret(Spec).getEncoded();

        //Creates a stringbuilder object
        StringBuilder HashBuilder = new StringBuilder();
        //Loops through the bytes in the byte array and converts each of them to hexadecimal
        //and appends to the stringbuilder
        for (int i = 0; i < HashBytes.length; i++) {
            HashBuilder.append(String.format("%02x", HashBytes[i]));
        }
        return HashBuilder.toString();
    }
    /*
    Name: CreateSalt
    Purpose: Creates a salt for a new user's password
    Author: Samuel McManus
    Uses: N/A
    Used By: HashPassword
    Date: September 14, 2020
     */
    static byte[] CreateSalt(){
        //Create a secure random number generator
        SecureRandom rng = new SecureRandom();
        //Make an 8-byte array for the salt
        byte[] Salt = new byte[8];
        //Fill the salt byte array with random numbers
        rng.nextBytes(Salt);
        return Salt;
    }
}
