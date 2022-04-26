package kr.re.nsr.crypto;

import com.github.jinahya.kisa.lea.LeaConstants;
import com.github.jinahya.kisa.lea.LeaTestUtils;
import kr.re.nsr.crypto.util.Hex;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.awt.*;
import java.security.SecureRandom;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
abstract class BlockCipherModeTest<T extends BlockCipherMode> {

    protected BlockCipherModeTest(final Class<T> modeClass) {
        super();
        this.modeClass = Objects.requireNonNull(modeClass, "modeClass is null");
    }

    protected T modeInstance() {
        try {
            final var constructor = modeClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            return constructor.newInstance();
        } catch (final ReflectiveOperationException roe) {
            throw new RuntimeException(roe);
        }
    }

    @Test
    void getAlgorithmName__() {
        final var algorithmName = modeInstance().getAlgorithmName();
    }

    @MethodSource({"kr.re.nsr.crypto.TestVectors#testVectorStream"})
    @ParameterizedTest
    void testVector__(final byte[] key, final byte[] plain, final byte[] encrypted) throws Exception {
        log.debug("      key: {}", Hex.toHexString(key));
        log.debug("    plain: {}", Hex.toHexString(plain));
        log.debug("encrypted: {}", Hex.toHexString(encrypted));
//        final var random = SecureRandom.getInstanceStrong();
        final T instance = modeInstance();
//        final byte[] iv = new byte[LeaConstants.BLOCK_BYTES];
        try {
            instance.init(BlockCipher.Mode.ENCRYPT, key);
        } catch (final Exception e) {
            Assumptions.assumeTrue(false);
//            instance.init(BlockCipher.Mode.ENCRYPT, key, iv);
        }
        final byte[] encrypted_ = instance.doFinal(plain);
        assertThat(encrypted_)
                .isNotNull()
                .isEqualTo(encrypted);
        try {
            instance.init(BlockCipher.Mode.DECRYPT, key);
        } catch (final Exception e) {
            Assumptions.assumeTrue(false);
//            instance.init(BlockCipher.Mode.DECRYPT, key, iv);
        }
        assertThat(instance.doFinal(encrypted_))
                .isNotNull()
                .isEqualTo(plain);
    }

    protected final Class<T> modeClass;
}