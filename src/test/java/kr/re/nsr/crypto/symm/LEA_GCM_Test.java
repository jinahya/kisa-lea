package kr.re.nsr.crypto.symm;

import com.github.jinahya.kisa.lea.AeadTestUtils;
import kr.re.nsr.crypto.BlockCipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class LEA_GCM_Test {

    @MethodSource({"kr.re.nsr.crypto.symm.LeaTests#keyBytesStream"})
    @ParameterizedTest
    void encrypt__(final byte[] key) throws NoSuchAlgorithmException {
        final var random = SecureRandom.getInstanceStrong();
        final var cipher = new LEA.GCM();
        final byte[] nonce = AeadTestUtils.nonceForGcm(random, 128);
        final byte[] aad = AeadTestUtils.aadForGcm(random);
        final int taglen = AeadTestUtils.tagLenForGcm(random);
        cipher.init(BlockCipher.Mode.ENCRYPT, key, nonce, taglen);
        cipher.updateAAD(aad);
        for (int i = 0; i < 4; i++) {
            final var msg = new byte[random.nextInt(16)];
            random.nextBytes(msg);
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
        final var cipher = new LEA.GCM();
        final byte[] plain;
        {
            plain = new byte[random.nextInt(8)];
            random.nextBytes(plain);
            log.debug("    plain: {}", plain);
        }
        final byte[] nonce = AeadTestUtils.nonceForGcm(random, 128);
        final int taglen = AeadTestUtils.tagLenForGcm(random);
        final byte[] aad = AeadTestUtils.aadForGcm(random);
        final byte[] encrypted;
        {
            cipher.init(BlockCipher.Mode.ENCRYPT, key, nonce, taglen);
            cipher.updateAAD(aad);
            encrypted = cipher.doFinal(plain);
            log.debug("encrypted: {}", encrypted);
        }
        final byte[] decrypted;
        {
            cipher.init(BlockCipher.Mode.DECRYPT, key, nonce, taglen);
            cipher.updateAAD(aad);
            decrypted = cipher.doFinal(encrypted);
            log.debug("decrypted: {}", decrypted);
        }
        assertThat(decrypted).isEqualTo(plain);
    }
}