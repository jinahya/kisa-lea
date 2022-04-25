package kr.re.nsr.crypto.symm;

import com.github.jinahya.kisa.lea.LeaConstants;
import kr.re.nsr.crypto.util.Hex;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class LEA_CMAC_Test {

    @MethodSource({"kr.re.nsr.crypto.symm.LeaTests#keyBytesStream"})
    @ParameterizedTest
    void test__(final byte[] key) throws NoSuchAlgorithmException {
        final var mac = new LEA.CMAC();
        mac.init(key);
        final var random = SecureRandom.getInstanceStrong();
        final byte[] plain;
        {
            plain = new byte[16 << random.nextInt(3)];
            random.nextBytes(plain);
        }
        final Set<Integer> set = new HashSet<>();
        for (int i = 0; i < 4; i++) {
            mac.reset();
            final var finalized = mac.doFinal(plain);
            log.debug("finalized: ({}) {}", finalized.length, Hex.toHexString(finalized));
            assertThat(finalized)
                    .hasSize(LeaConstants.BLOCK_BYTES);
            if (set.isEmpty()) {
                set.add(Arrays.hashCode(finalized));
            } else {
                assertThat(set.add(Arrays.hashCode(finalized))).isFalse();
            }
        }
    }
}