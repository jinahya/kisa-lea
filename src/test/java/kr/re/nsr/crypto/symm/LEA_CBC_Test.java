package kr.re.nsr.crypto.symm;

import com.github.jinahya.kisa.lea.LeaConstants;
import com.github.jinahya.kisa.lea.LeaTestUtils;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.padding.PKCS5Padding;
import kr.re.nsr.crypto.util.Hex;
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
        final byte[] iv = LeaTestUtils.iv(random);
        cipher.init(BlockCipher.Mode.ENCRYPT, key, iv);
        cipher.setPadding(new PKCS5Padding(LeaConstants.BLOCK_BYTES));
        for (int i = 0; i < 4; i++) {
            final byte[] msg = new byte[random.nextInt(1024)];
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
        final var cipher = new LEA.CBC();
        final byte[] iv = LeaTestUtils.iv(random);
        final byte[] plain;
        {
            plain = new byte[random.nextInt(8)];
            random.nextBytes(plain);
            log.debug("    plain: {}", Hex.toHexString(plain));
        }
        final byte[] encrypted;
        {
            cipher.init(BlockCipher.Mode.ENCRYPT, key, iv);
            cipher.setPadding(new PKCS5Padding(LeaConstants.BLOCK_BYTES));
            encrypted = cipher.doFinal(plain);
            log.debug("encrypted: {}", Hex.toHexString(encrypted));
            assertThat(encrypted.length)
                    .satisfies(l -> {
                        assertThat(l % LeaConstants.BLOCK_BYTES)
                                .isZero();
                    });
        }
        final byte[] decrypted;
        {
            cipher.reset();
            cipher.init(BlockCipher.Mode.DECRYPT, key, iv);
            cipher.setPadding(new PKCS5Padding(LeaConstants.BLOCK_BYTES));
            decrypted = cipher.doFinal(encrypted);
            log.debug("decrypted: {}", Hex.toHexString(decrypted));
        }
        assertThat(decrypted).isEqualTo(plain);
    }
}