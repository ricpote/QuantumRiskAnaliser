import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

// Fixture: the AES key size of a Cipher must come from its own method, or be left unresolved
// when the file creates keys of different sizes elsewhere (never "the last KeyGenerator wins").
public class KeySizes {
    void archiveKey() throws Exception {
        KeyGenerator k = KeyGenerator.getInstance("AES");
        k.init(256);
    }

    void sealRecord() throws Exception {
        KeyGenerator k = KeyGenerator.getInstance("AES");
        k.init(256);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    }

    void openFeed() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    }

    void legacyKey() throws Exception {
        KeyGenerator k = KeyGenerator.getInstance("AES");
        k.init(128);
    }
}
