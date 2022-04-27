package kr.re.nsr.crypto;

import org.junit.jupiter.params.provider.Arguments;

import java.io.ByteArrayOutputStream;
import java.io.ObjectInput;
import java.util.Arrays;
import java.util.stream.Stream;

public final class TestVectors {

    private static byte[] array(final String string) {
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        Arrays.stream(string.split("\\s"))
                .map(String::strip)
                .mapToInt(v -> Integer.parseInt(v, 16))
                .forEach(stream::write);
        return stream.toByteArray();
    }

    public static Stream<Arguments> testVectorStream() {
        return Stream.of(
                Arguments.of(
                        array("0f 1e 2d 3c 4b 5a 69 78 "
                              + "87 96 a5 b4 c3 d2 e1 f0"),
                        array("10 11 12 13 14 15 16 17 "
                              + "18 19 1a 1b 1c 1d 1e 1f"),
                        array("9f c8 4e 35 28 c6 c6 18 "
                              + "55 32 c7 a7 04 64 8b fd")
                ),
                Arguments.of(
                        array("0f 1e 2d 3c 4b 5a 69 78 "
                              + "87 96 a5 b4 c3 d2 e1 f0 "
                              + "f0 e1 d2 c3 b4 a5 96 87"),
                        array("20 21 22 23 24 25 26 27 "
                              + "28 29 2a 2b 2c 2d 2e 2f"),
                        array("6f b9 5e 32 5a ad 1b 87 "
                              + "8c dc f5 35 76 74 c6 f2")
                ),
                Arguments.of(
                        array("0f 1e 2d 3c 4b 5a 69 78 "
                              + "87 96 a5 b4 c3 d2 e1 f0 "
                              + "f0 e1 d2 c3 b4 a5 96 87 "
                              + "78 69 5a 4b 3c 2d 1e 0f"),
                        array("30 31 32 33 34 35 36 37 "
                              + "38 39 3a 3b 3c 3d 3e 3f"),
                        array("d6 51 af f6 47 b1 89 c1 "
                              + "3a 89 00 ca 27 f9 e1 97")
                )
        );
    }

    private TestVectors() {
        throw new AssertionError("instantiation is not allowed");
    }
}
