package com.github.jinahya.kisa.lea;

import java.util.Objects;
import java.util.Random;

public final class LeaTestUtils {

    public static byte[] iv(final Random random) {
        Objects.requireNonNull(random, "random is null");
        final var iv = new byte[LeaConstants.BLOCK_BYTES];
        random.nextBytes(iv);
        return iv;
    }

    private LeaTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
