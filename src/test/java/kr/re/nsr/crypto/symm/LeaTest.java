package kr.re.nsr.crypto.symm;

import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.padding.PKCS5Padding;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static java.util.concurrent.ThreadLocalRandom.current;

@Slf4j
class LeaTest {

    @Test
    void encrypt__() {
        LeaTests.acceptBlockCipherModeBlockInstances(c -> {
            try {
                c.reset();
            } catch (final NullPointerException npe) {
            }
            LeaTests.acceptKeys(k -> {
                try {
                    c.init(BlockCipher.Mode.ENCRYPT, k, k);
                } catch (final IllegalStateException ise) {
                    c.init(BlockCipher.Mode.ENCRYPT, k);
                }
                c.setPadding(new PKCS5Padding(16));
                for (int i = 0; i < 8; i++) {
                    final var msg = new byte[current().nextInt(1024)];
                    c.update(msg);
                    final var finalized = c.doFinal();
                }
            });
        });
    }
}