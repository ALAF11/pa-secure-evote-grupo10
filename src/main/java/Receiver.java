import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Receiver implements Runnable {

    private final ServerSocket server;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private Socket client;

    public Receiver(int port) throws IOException {
        server = new ServerSocket(port);
    }

    @Override
    public void run() {
        try {
            client = server.accept();
            in = new ObjectInputStream(client.getInputStream());
            out = new ObjectOutputStream(client.getOutputStream());
            // Process the request
            process(in);
            // Close connection
            closeConnection();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void process ( ObjectInputStream in ) throws Exception {
        // Reads the message object
        Message messageObj = ( Message ) in.readObject ( );
        System.out.println ( new String ( messageObj.getMessage ( ) ) );
    }

    private void closeConnection() throws IOException {
        client.close();
        out.close();
        in.close();
    }
}
