import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

public class CBC {

    public static byte[] encrypt(byte[] text, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        ArrayList<byte[]> splits = ByteUtils.splitByteArray(text, 16) ;
        byte[] encryptedContent = new byte[0];
        byte[] xorOperand = iv;

        for (byte[] split : splits) {
            byte[] splitXOR = ByteUtils.xorByteArrays(split, xorOperand);
            byte[] encryptedSplit = cipher.doFinal(splitXOR);
            encryptedContent = ByteUtils.concatByteArrays(encryptedContent, encryptedSplit);
            xorOperand = encryptedSplit;
        }
        return encryptedContent;
    }

    public static byte[] decrypt(byte[] text, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        ArrayList<byte[]> splits = ByteUtils.splitByteArray(text, 16);
        byte[] decryptedContent = new byte[0];
        byte[] xorOperand = iv;

        for (byte[] split : splits) {
            byte[] decryptedSplit = cipher.doFinal(split);
            byte[] decryptedSplitXOR = ByteUtils.xorByteArrays(decryptedSplit, xorOperand);
            decryptedContent = ByteUtils.concatByteArrays(decryptedContent, decryptedSplitXOR);
            xorOperand = split;
        }
        int padding = decryptedContent[decryptedContent.length - 1];
        return Arrays.copyOfRange(decryptedContent, 0, decryptedContent.length - padding);
    }
}
