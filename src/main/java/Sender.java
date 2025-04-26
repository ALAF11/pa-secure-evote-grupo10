import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class Sender {

    private static final String HOST = "0.0.0.0";
    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;

    public Sender(int port) throws IOException {
        client = new Socket(HOST, port);
        out = new ObjectOutputStream(client.getOutputStream());
        in = new ObjectInputStream(client.getInputStream());
    }

    public void sendMessage(String message) throws Exception {
        // Creates the message object
        Message messageObj = new Message(message.getBytes());
        // Sends the message
        out.writeObject(messageObj);
        // Close connection
        closeConnection();
    }

    private void closeConnection() throws IOException {
        client.close();
        out.close();
        in.close();
    }

}
