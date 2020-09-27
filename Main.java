import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Semaphore;

public class Main {
    public static void main(String []args) {
        int CountClients = 1;
        try {
            //Creates a server socket listening on port 6622 with a queue of 8
            ServerSocket serverSocket = new ServerSocket(6622, 8);
            while (true) {
                Socket ClientServer = serverSocket.accept();
                Semaphore sem = new Semaphore(1);
                System.out.println("Starting client server" + CountClients);
                new Networking(ClientServer, CountClients, sem).start();
                CountClients++;
            }
        } catch (Exception e){
            System.out.println(e);
        }
    }
}