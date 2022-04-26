package com.github.jinahya.kisa.lea;

import java.util.Arrays;
import java.util.List;

public final class LEAConstants {

    /**
     * The name of the LEA algorithm. The value is {@value}.
     */
    public static final String ALGORITHM_NAME = "LEA";

    /**
     * The block size, in bits, of LEA. The value is {@value}.
     */
    public static final int BLOCK_SIZE = 128;

    /**
     * The block size, in bytes, of LEA. The value is {@value}.
     */
    public static final int BLOCK_BYTES = 16;

    /**
     * An unmodifiable list of applicable key sizes which contains {@code 128}, {@code 192}, and {@code 256}.
     */
    static final List<Integer> KEY_SIZES = Arrays.asList(128, 192, 256);

    private LEAConstants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
