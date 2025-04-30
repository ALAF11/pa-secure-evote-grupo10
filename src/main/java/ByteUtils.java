import java.util.ArrayList;
import java.util.Arrays;

public class ByteUtils {

    public static ArrayList<byte[]> splitByteArray(byte[] text, int chunkSize) {
        ArrayList<byte[]> result = new ArrayList<>();
        for (int i = 0; i < text.length; i += chunkSize) {
            byte[] chunk = Arrays.copyOfRange(text, i, Math.min(text.length, i + chunkSize));
            result.add(chunk);
        }

        byte[] lastChunk = result.get(result.size() - 1);
        if (lastChunk.length < chunkSize) {
            byte[] paddedChunk = new byte[chunkSize];
            int padding = chunkSize - lastChunk.length;
            System.arraycopy(lastChunk, 0, paddedChunk, 0, lastChunk.length);
            for (int i = lastChunk.length; i < chunkSize; i++) {
                paddedChunk[i] = (byte) padding;
            }
            result.set(result.size() - 1, paddedChunk);
        }
        return result;
    }

    public static byte[] concatByteArrays(byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }

    public static byte[] xorByteArrays(byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length];
        for (int i = 0; i < array1.length; i++) {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }
        return result;
    }

    public static void fillByteArray(byte[] array, byte value) {
        Arrays.fill(array, value);
    }
}