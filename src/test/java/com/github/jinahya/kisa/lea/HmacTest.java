package com.github.jinahya.kisa.lea;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class HmacTest {

    private static Stream<String> algorithms() {
        return Stream.of("HmacMD5", "HmacSHA1", "HmacSHA256");
    }

    @ValueSource(strings = {"HmacMD5", "HmacSHA1", "HmacSHA256"})
    @ParameterizedTest
    void test(final String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        final var random = SecureRandom.getInstanceStrong();
        final byte[] key = new byte[128];
        random.nextBytes(key);
        final var keySpec = new SecretKeySpec(key, algorithm);
        final byte[] plain;
        {
            plain = new byte[random.nextInt(128)];
            random.nextBytes(plain);
        }
        final Base64.Encoder base64 = Base64.getEncoder();
        final Set<Integer> set = new HashSet<>();
        for (int i = 0; i < 4; i++) {
            final Mac mac = Mac.getInstance(algorithm);
            mac.init(keySpec);
            final byte[] finalized = mac.doFinal();
            log.debug("finalized: ({}) {}", finalized.length, base64.encodeToString(finalized));
            if (set.isEmpty()) {
                set.add(Arrays.hashCode(finalized));
            } else {
                assertThat(set.add(Arrays.hashCode(finalized))).isFalse();
            }
        }
    }
}
