import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.Semaphore;

public class Networking extends Thread{
    private Socket io;
    private int CountClients;
    private Semaphore Sema;

    public Networking(Socket i, int c, Semaphore Sema){
        io = i;
        CountClients = c;
        this.Sema = Sema;
    }
    /*
    Name: Listen
    Purpose: Listens for connecting users
    Author: Samuel McManus
    Uses: Verification.Register, Verification.Login
    Used By: Main
    Date: September 14, 2020
     */
    public void run(){
        try {
                //Attach a reader stream to the socket
                ObjectInputStream Input = new ObjectInputStream(
                        io.getInputStream());
                //Attach a writer stream to the socket which
                //auto-flushes (automatically sends data back)
                ObjectOutputStream Output = new ObjectOutputStream(
                        io.getOutputStream());
                //Clears out the initial garbage stored in the output of the client socket
                Input.readObject();
                boolean Verified = VerifyUser(Input, Output, this.Sema);
                //If the user successfully verified their account, then start the rest of the program
                if(Verified){
                    //Generate a secret session key using Diffie-Hellman
                    byte[] SessionKey = Cryptography.DiffieHellman(Input, Output);
                    //Hash the session key to make it a reasonable size
                    byte[] SmallSessionKey = Cryptography.SHAHash(SessionKey);
                    String AlgorithmChoice = (String)Input.readObject();
                    switch(AlgorithmChoice){
                        case "1":
                            SecretKey DESKey = Cryptography.DESKeyGen(SmallSessionKey);
                            Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding");
                            //Gets the IV and IV length
                            byte[] IV = (byte[]) Input.readObject();
                            //Creates the IV parameter spec and re-initializes the cipher
                            IvParameterSpec ivps = new IvParameterSpec(IV);
                            des.init(Cipher.DECRYPT_MODE, DESKey, ivps);
                            ReceiveFile(Input, des);
                            des.init(Cipher.ENCRYPT_MODE, DESKey);
                            Sema.acquire();
                            SendFile(des, Output);
                            Sema.release();
                        case "2":
                            SecretKeySpec BlowfishKey =
                                    Cryptography.BlowfishKeyGen(SmallSessionKey);
                            Cipher Blowfish = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
                            IV = (byte[]) Input.readObject();
                            ivps = new IvParameterSpec(IV);
                            Blowfish.init(Cipher.DECRYPT_MODE, BlowfishKey, ivps);
                            ReceiveFile(Input, Blowfish);
                            Blowfish.init(Cipher.ENCRYPT_MODE, BlowfishKey);
                            Sema.acquire();
                            SendFile(Blowfish, Output);
                            Sema.release();
                        case "3":
                            SecretKey DESedeKey = Cryptography.DESedeKeyGen(SmallSessionKey);
                            Cipher DESede = Cipher.getInstance("DESede/CBC/PKCS5Padding");
                            IV = (byte[]) Input.readObject();
                            ivps = new IvParameterSpec(IV);
                            DESede.init(Cipher.DECRYPT_MODE, DESedeKey, ivps);
                            ReceiveFile(Input, DESede);
                            DESede.init(Cipher.ENCRYPT_MODE, DESedeKey);
                            Sema.acquire();
                            SendFile(DESede, Output);
                            Sema.release();
                    }
                }
                //Close the reader, writer, and socket.
                Input.close();
                Output.close();
                io.close();
            } catch (InvalidKeySpecException invalidKeySpecException) {
            invalidKeySpecException.printStackTrace();
        } catch (ClassNotFoundException classNotFoundException) {
            classNotFoundException.printStackTrace();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            noSuchAlgorithmException.printStackTrace();
        } catch (BadPaddingException badPaddingException) {
            badPaddingException.printStackTrace();
        } catch (InvalidKeyException invalidKeyException) {
            invalidKeyException.printStackTrace();
        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            invalidAlgorithmParameterException.printStackTrace();
        } catch (NoSuchPaddingException noSuchPaddingException) {
            noSuchPaddingException.printStackTrace();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        } catch (IllegalBlockSizeException illegalBlockSizeException) {
            illegalBlockSizeException.printStackTrace();
        } catch (InterruptedException interruptedException) {
            interruptedException.printStackTrace();
        }
    }
    /*
    Name: VerifyUser
    Purpose: Verifies a user's account
    Author: Samuel McManus
    Uses: Verification.Register, Verification.Login
    Used By: Main
    Date: September 14, 2020
     */
    static boolean VerifyUser(ObjectInputStream Input, ObjectOutputStream Output,
                              Semaphore Sema) throws IOException, ClassNotFoundException,
            InvalidKeySpecException, NoSuchAlgorithmException, InterruptedException {
        //Takes user credentials
        String UserInput = (String)Input.readObject();
        String[] UserCredentials = UserInput.split(", ");
        //Registers a new user
        if(UserCredentials[2].trim().equalsIgnoreCase("New")) {
            //If the following returns false, then the username is unavailable
            if (!Verification.Register(UserCredentials[0], UserCredentials[1], Sema)) {
                Output.writeObject("Username not available\n");
            } else {
                Output.writeObject("Success! Next please log in\n");
            }
            Output.flush();
            return false;
        }
        //Logs a user in
        else {
            //If the user's input credentials don't match the actuals, tell the user
            //they messed up and return false
            if(!Verification.Login(UserCredentials[0], UserCredentials[1], Sema)){
                Output.writeObject("Invalid username or password");
                Output.flush();
                return false;
            }
            //If the user's input credentials match the actuals, tell the user
            //they succeeded and return true
            else{
                Output.writeObject("Success!");
                Output.flush();
                return true;
            }
        }
    }
    /*
    Name: SendFile
    Purpose: Send a file to the client
    Author: Samuel McManus
    Parameter MyCipher: The cipher used to encrypt the message
    Parameter Output: The output socket
    Uses: Cryptography.Encrypt
    Used By: Connect
    Date: September 22, 2020
     */
    public static void SendFile(Cipher MyCipher, ObjectOutputStream Output) throws
            IOException, IllegalBlockSizeException, BadPaddingException,
            InterruptedException {
        //Read the plaintext of the file
        IO.ReadPlaintext();
        //Encrypt the file using the DES method
        Cryptography.Encrypt(MyCipher, Output);
    }
    /*
    Name: ReceiveFile
    Purpose: Receive a file from the client
    Author: Samuel McManus
    Parameter MyCipher: The cipher used to encrypt the message
    Parameter Input: The input socket used to communicate with the server
    Uses: Cryptography.Decrypt
    Used By: Connect
    Date: September 22, 2020
     */
    public static void ReceiveFile(ObjectInputStream Input, Cipher MyCipher) throws
            IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException {
        //Gets the cipher text from the server
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        while(true){
            byte[] TempCipher = (byte[]) Input.readObject();
            if(Arrays.equals(TempCipher, "finished".getBytes()))
                break;
            bo.writeBytes(TempCipher);
        }
        //Converts the cipher text to an array of bytes
        byte[] CipherText = bo.toByteArray();
        System.out.println("\nCiphertext received from client:");
        System.out.println(new String(CipherText));
        Cryptography.Decrypt(MyCipher, CipherText);
    }
}
