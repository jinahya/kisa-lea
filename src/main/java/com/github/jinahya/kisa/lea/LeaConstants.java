package com.github.jinahya.kisa.lea;

import java.util.Arrays;
import java.util.List;

/**
 * Constants related to the LEA cipher.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class LeaConstants {

    static final String ALGORITHM = "AES";

    static final String MODE_ECB = "ECB";

    static final String MODE_CBC = "CBC";

    static final String MODE_CTR = "CTR";

    static final String MODE_CFB = "CFB";

    static final String MODE_OFB = "OFB";

    static final String MODE_CCM = "CCM";

    static final String MODE_GCM = "GCM";

    static final String PADDING_PKCS5_PADDING = "PKCS5Padding";

    static final String PADDING_NO_PADDING = "NoPadding";

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

    private LeaConstants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
