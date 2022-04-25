package kr.re.nsr.crypto.symm;

import com.github.jinahya.kisa.lea.LeaConstants;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.padding.PKCS5Padding;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class LEA_ECB_Test {

    @MethodSource({"kr.re.nsr.crypto.symm.LeaTests#keyBytesStream"})
    @ParameterizedTest
    void encrypt__(final byte[] key) throws NoSuchAlgorithmException {
        final var random = SecureRandom.getInstanceStrong();
        final var cipher = new LEA.ECB();
        cipher.init(BlockCipher.Mode.ENCRYPT, key);
        cipher.setPadding(new PKCS5Padding(LeaConstants.BLOCK_BYTES));
        for (int i = 0; i < 4; i++) {
            final var msg = new byte[random.nextInt(128)];
            random.nextBytes(msg);
            final var result = cipher.update(msg);
            assertThat(result).isNotNull();
        }
        final var encrypted = cipher.doFinal();
        log.debug("encrypted: {}", encrypted);
        assertThat(encrypted).isNotEmpty();
    }

    @MethodSource({"kr.re.nsr.crypto.symm.LeaTests#keyBytesStream"})
    @ParameterizedTest
    void decrypt__(final byte[] key) throws NoSuchAlgorithmException {
        final var random = SecureRandom.getInstanceStrong();
        final var cipher = new LEA.ECB();
        final byte[] plain;
        {
            plain = new byte[random.nextInt(8)];
            random.nextBytes(plain);
            log.debug("    plain: {}", plain);
        }
        final byte[] encrypted;
        {
            cipher.init(BlockCipher.Mode.ENCRYPT, key);
            cipher.setPadding(new PKCS5Padding(LeaConstants.BLOCK_BYTES));
            encrypted = cipher.doFinal(plain);
            log.debug("encrypted: {}", encrypted);
            assertThat(encrypted.length)
                    .satisfies(l -> {
                        assertThat(l % LeaConstants.BLOCK_BYTES)
                                .isZero();
                    });
        }
        final byte[] decrypted;
        {
            cipher.reset();
            cipher.init(BlockCipher.Mode.DECRYPT, key);
            cipher.setPadding(new PKCS5Padding(LeaConstants.BLOCK_BYTES));
            decrypted = cipher.doFinal(encrypted);
            log.debug("decrypted: {}", decrypted);
        }
        assertThat(decrypted).isEqualTo(plain);
    }
}