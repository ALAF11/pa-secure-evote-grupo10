import java.io.IOException;

public class MainReceiver {

    public static void main(String[] args) throws IOException {
        Receiver receiver = new Receiver ( 8000 );
        Thread serverThread = new Thread ( receiver );
        serverThread.start ( );
    }
}
