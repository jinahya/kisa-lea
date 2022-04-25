package com.github.jinahya.kisa.lea;

import java.util.Objects;
import java.util.Random;

public final class AeadTestUtils {

    public static byte[] nonceForCcm(final Random random) {
        Objects.requireNonNull(random, "random is null");
        final byte[] nonce = new byte[random.nextInt(7) + 7];
        random.nextBytes(nonce);
        return nonce;
    }

    public static int taglenForCcm(final Random random) {
        Objects.requireNonNull(random, "random is null");
        return (random.nextInt(7) + 2) << 1;
    }

    public static byte[] aadForCcm(final Random random) {
        Objects.requireNonNull(random, "random is null");
        final byte[] aad = new byte[random.nextInt(65536)];
        random.nextBytes(aad);
        return aad;
    }

    public static byte[] nonceForGcm(final Random random, final int bound) {
        Objects.requireNonNull(random, "random is null");
        final byte[] nonce = new byte[random.nextInt(bound) + 1];
        random.nextBytes(nonce);
        return nonce;
    }

    public static int tagLenForGcm(final Random random) {
        return random.nextInt(13) + 4;
    }

    public static byte[] aadForGcm(final Random random) {
        final byte[] aad = new byte[random.nextInt(65536)];
        random.nextBytes(aad);
        return aad;
    }

    private AeadTestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
