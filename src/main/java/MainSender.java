import java.util.Scanner;

public class MainSender {

    public static void main(String[] args) throws Exception {
        Sender sender = new Sender(8000);
        Scanner usrInput = new Scanner(System.in);
        System.out.println("Write the message to send");
        String message = usrInput.nextLine();
        sender.sendMessage(message);
    }
}
