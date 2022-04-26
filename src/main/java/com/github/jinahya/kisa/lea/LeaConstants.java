package com.github.jinahya.kisa.lea;

import java.util.Arrays;
import java.util.List;

public final class LEAConstants {

    public static final String ALGORITHM = "AES";

    public static final String MODE_ECB = "ECB";

    public static final String MODE_CBC = "CBC";

    public static final String MODE_CTR = "CTR";

    public static final String MODE_CFB = "CFB";

    public static final String MODE_OFB = "OFB";

    public static final String MODE_CCM = "CCM";

    public static final String MODE_GCM = "GCM";

    public static final String PADDING_PKCS5_PADDING = "PKCS5Padding";

    public static final String PADDING_NO_PADDING = "NoPadding";

    /**
     * The block size, in bits, of LEA. The value is {@value}.
     */
    static final int BLOCK_SIZE = 128;

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
