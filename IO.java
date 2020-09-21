import java.io.*;

public class IO {
    /*
    Name: SearchForUser
    Purpose: Checks to see if the username entered is already in use
    Author: Samuel McManus
    Return: Whether the user's username already exists
    Uses: N/A
    Used By: Register
    Date: September 15, 2020
     */
    static boolean SearchForUser(String Username) throws IOException {
        //Creates a file object for the Credentials text file and opens up a buffered reader
        File CredentialFile = new File("Credentials.txt");
        BufferedReader FileReader = new BufferedReader(new FileReader(CredentialFile));
        //Loops through the whole file looking to see if the username already exists. If so,
        //return true.
        String FileLine;
        String[] UserCreds;
        while((FileLine = FileReader.readLine())!= null){
            UserCreds = FileLine.split(", ");
            if(UserCreds[0].equalsIgnoreCase(Username)) {
                FileReader.close();
                return true;
            }
        }
        FileReader.close();
        return false;
    }
    /*
    Name: GetUser
    Purpose: Gets a user's details from the credential file
    Author: Samuel McManus
    Return: The user's credentials
    Uses: N/A
    Used By: Register
    Date: September 15, 2020
     */
    static String[] GetUser(String Username) throws IOException {
        //Creates a file object for the Credentials text file and opens up a buffered reader
        File CredentialFile = new File("Credentials.txt");
        BufferedReader FileReader = new BufferedReader(new FileReader(CredentialFile));

        //Loops through the whole file looking to see if the username already exists. If so,
        //return the user's credentials.
        String FileLine;
        String[] UserCreds;
        while((FileLine = FileReader.readLine())!= null){
            UserCreds = FileLine.split(", ");
            if(UserCreds[0].equalsIgnoreCase(Username)) {
                FileReader.close();
                return UserCreds;
            }
        }
        //If the user doesn't exist, return nothing.
        FileReader.close();
        return new String[3];
    }
    /*
    Name: WriteNewUser
    Purpose: Writes a new user to the credentials file
    Author: Samuel McManus
    Parameter Username: The user's username
    Parameter PasswordHash: The user's password hash
    Parameter Salt: The password's salt
    Uses: N/A
    Used By: Register
    Date: September 15, 2020
     */
    static void WriteNewUser(String Username, String PasswordHash, String Salt) throws IOException {
        BufferedWriter FileWriter = new BufferedWriter(new FileWriter("Credentials.txt", true));
        FileWriter.append(Username + ", " + PasswordHash + ", " + Salt + "\n");
        FileWriter.close();
    }
}
