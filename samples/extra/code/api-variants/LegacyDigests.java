import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NullCipher;
import org.apache.commons.codec.digest.DigestUtils;

public class LegacyDigests {
    public String token(String data) {
        return DigestUtils.md5Hex(data);
    }

    public byte[] audit(byte[] data) {
        return DigestUtils.getSha1Digest().digest(data);
    }

    public Cipher passthrough() {
        return new NullCipher();
    }

    public void legacyKey() throws Exception {
        KeyGenerator.getInstance("DESede").generateKey();
    }

    public void signingKeys() throws Exception {
        KeyPairGenerator weak = KeyPairGenerator.getInstance("RSA");
        weak.initialize(512);
        KeyPairGenerator strong = KeyPairGenerator.getInstance("RSA");
        strong.initialize(4096);
    }
}
