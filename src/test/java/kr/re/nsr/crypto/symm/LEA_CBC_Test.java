package kr.re.nsr.crypto.symm;

import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.padding.PKCS5Padding;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class LEA_CBC_Test {

    @MethodSource({"kr.re.nsr.crypto.symm.LeaTests#keyBytesStream"})
    @ParameterizedTest
    void encrypt__(final byte[] key) throws NoSuchAlgorithmException {
        final var random = SecureRandom.getInstanceStrong();
        final var cipher = new LEA.CBC();
        final byte[] iv;
        {
            iv = new byte[16];
            random.nextBytes(iv);
        }
        cipher.init(BlockCipher.Mode.ENCRYPT, key, iv);
        cipher.setPadding(new PKCS5Padding(16));
        for (int i = 0; i < 8; i++) {
            final byte[] msg;
            {
                msg = new byte[random.nextInt(1024)];
                random.nextBytes(msg);
            }
            cipher.update(msg);
        }
        final var encrypted = cipher.doFinal();
        log.debug("encrypted: {}", encrypted);
        assertThat(encrypted).isNotEmpty();
    }

    @MethodSource({"kr.re.nsr.crypto.symm.LeaTests#keyBytesStream"})
    @ParameterizedTest
    void decrypt__(final byte[] key) throws NoSuchAlgorithmException {
        final var random = SecureRandom.getInstanceStrong();
        final var cipher = new LEA.CBC();
        final byte[] iv;
        {
            iv = new byte[16];
            random.nextBytes(iv);
        }
        final byte[] plain;
        {
            plain = new byte[random.nextInt(8)];
            random.nextBytes(plain);
            log.debug("    plain: {}", plain);
        }
        final byte[] encrypted;
        {
            cipher.init(BlockCipher.Mode.ENCRYPT, key, iv);
            cipher.setPadding(new PKCS5Padding(16));
            encrypted = cipher.doFinal(plain);
            log.debug("encrypted: {}", encrypted);
        }
        final byte[] decrypted;
        {
            cipher.reset();
            cipher.init(BlockCipher.Mode.DECRYPT, key, iv);
            cipher.setPadding(new PKCS5Padding(16));
            decrypted = cipher.doFinal(encrypted);
            log.debug("decrypted: {}", decrypted);
        }
        assertThat(decrypted).isEqualTo(plain);
    }
}