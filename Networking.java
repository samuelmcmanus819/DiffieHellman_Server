import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Networking{
    /*
    Name: Listen
    Purpose: Listens for connecting users
    Author: Samuel McManus
    Uses: N/A
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
                //Continues until an event triggers finished to equal true
                boolean finished = false;
                //Clears out the initial garbage stored in the output of the client socket
                Input.readObject();

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
                }
                //Logs a user in
                else {
                    if(!Verification.Login(UserCredentials[0], UserCredentials[1])){
                        Output.writeObject("Invalid username or password");
                        Output.flush();
                    }
                }

                while (!finished) {
                    /*
                    EVERYTHING HERE IS TEMPRORARY
                    all this does is echo what the user entered in the terminal
                     */
                    UserInput = (String)Input.readObject();
                    if (UserInput.equals(""))
                        finished = true;
                    else {
                        System.out.println(UserInput);
                    }
                }
                //Close the reader, writer, and socket.
                Input.close();
                Output.close();
                IO.close();
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    /*
    Name: GetInput
    Purpose: Gets the client's input without the random nonsense
             added by the socket
    Author: Samuel McManus
    Return: The user's scrubbed input
    Uses: Listen
    Used By: Main
    Date: September 15, 2020
     */
    /*
    static String GetInput(ObjectInputStream Input) throws IOException, ClassNotFoundException {
        String UserInput = (String)Input.readObject();
        return UserInput;
        //return UserInput.substring(3);
    }
    */
}
