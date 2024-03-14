package one.d4d.dangerous;

import one.d4d.dangerous.keys.SecretKey;
import one.d4d.dangerous.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class CompressTest {
    @Test
    void Base64EncodedTimestampTest() {
        try {
            String expectedValue = ".eJxTKkstqlSgIpGTn5eukJyfV5KaV6IEAJM1I3A";
            byte[] decArray = Utils.base64Decompress(expectedValue.getBytes());
            String realValue = Utils.compressBase64(decArray);
            assertArrayEquals(expectedValue.toCharArray(), realValue.toCharArray());
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }
    @Test
    void SerializeDeserializeTest() {
        List<SecretKey> keys = Utils.readDefaultSecrets(this.getClass());
        Utils.serializeToFile(keys);
    }

}
