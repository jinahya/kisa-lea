package kr.re.nsr.crypto.symm;

import kr.re.nsr.crypto.BlockCipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class LEA_CFB_Test {

    @MethodSource({"kr.re.nsr.crypto.symm.LeaTests#keyBytesStream"})
    @ParameterizedTest
    void encrypt__(final byte[] key) throws NoSuchAlgorithmException {
        final var random = SecureRandom.getInstanceStrong();
        final var cipher = new LEA.CFB();
        final byte[] iv;
        {
            iv = new byte[16];
            random.nextBytes(iv);
        }
        cipher.init(BlockCipher.Mode.ENCRYPT, key, iv);
        final byte[] plain;
        {
            plain = new byte[16 << random.nextInt(3)];
            random.nextBytes(plain);
        }
        final var encrypted = cipher.doFinal(plain);
        log.debug("encrypted: {}", encrypted);
        assertThat(encrypted).isNotEmpty();
    }

    @MethodSource({"kr.re.nsr.crypto.symm.LeaTests#keyBytesStream"})
    @ParameterizedTest
    void decrypt__(final byte[] key) throws NoSuchAlgorithmException {
        final var random = SecureRandom.getInstanceStrong();
        final var cipher = new LEA.CFB();
        final byte[] iv;
        {
            iv = new byte[16];
            random.nextBytes(iv);
        }
        final byte[] plain;
        {
            plain = new byte[16 << random.nextInt(3)];
            random.nextBytes(plain);
            log.debug("    plain: {}", plain);
        }
        final byte[] encrypted;
        {
            cipher.init(BlockCipher.Mode.ENCRYPT, key, iv);
            encrypted = cipher.doFinal(plain);
            log.debug("encrypted: {}", encrypted);
        }
        final byte[] decrypted;
        {
            cipher.reset();
            cipher.init(BlockCipher.Mode.DECRYPT, key, iv);
            decrypted = cipher.doFinal(encrypted);
            log.debug("decrypted: {}", decrypted);
        }
        assertThat(decrypted).isEqualTo(plain);
    }
}