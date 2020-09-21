import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class Networking{
    /*
    Name: Listen
    Purpose: Listens for connecting users
    Author: Samuel McManus
    Uses: Verification.Register, Verification.Login
    Used By: Main
    Date: September 14, 2020
     */
    static void Listen() {
        try {
            //Creates a server socket listening on port 6622 with a queue of 8
            ServerSocket serverSocket = new ServerSocket(6622, 8);
            while (true) {
                //Creates a socket to send and receive messages and blocks any other activity
                //while waiting for a connection
                Socket IO = serverSocket.accept();
                //Attach a reader stream to the socket
                ObjectInputStream Input = new ObjectInputStream(
                        IO.getInputStream());
                //Attach a writer stream to the socket which
                //auto-flushes (automatically sends data back)
                ObjectOutputStream Output = new ObjectOutputStream(
                        IO.getOutputStream());
                //Clears out the initial garbage stored in the output of the client socket
                Input.readObject();

                //If the user successfully verified their account, then start the rest of the program
                if(VerifyUser(Input, Output)){
                    //Generate a secret session key using Diffie-Hellman
                    byte[] SessionKey = Cryptography.DiffieHellman(Input, Output);
                    //Hash the session key to make it a reasonable size
                    byte[] SmallSessionKey = Cryptography.SHA1Hash(SessionKey);
                    SecretKey DESKey = Cryptography.DESKeyGen(SmallSessionKey);
                }
                //Close the reader, writer, and socket.
                Input.close();
                Output.close();
                IO.close();
            }
        } catch (IOException | ClassNotFoundException | InvalidKeySpecException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }
    static boolean VerifyUser(ObjectInputStream Input, ObjectOutputStream Output) throws IOException, ClassNotFoundException, InvalidKeySpecException, NoSuchAlgorithmException {
        //Takes user credentials
        String UserInput = (String)Input.readObject();
        String[] UserCredentials = UserInput.split(", ");
        //Registers a new user
        if(UserCredentials[2].trim().equalsIgnoreCase("New")) {
            //If the following returns false, then the username is unavailable
            if (!Verification.Register(UserCredentials[0], UserCredentials[1])) {
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
            if(!Verification.Login(UserCredentials[0], UserCredentials[1])){
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
}
