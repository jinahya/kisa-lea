package com.github.jinahya.kisa.lea;

import kr.re.nsr.crypto.engine.LeaEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;

class LeaConstantsTest {

    @Test
    void BLOCK_SIZE__() {
        assertThat(LeaConstants.BLOCK_SIZE) // NOSONAR
                .satisfies(v -> {
                    assertThat(v % Byte.SIZE).isZero();
                });
    }

    @DisplayName("BLOCK_BYTES == LeaEngine.BLOCKSIZE")
    @Test
    void BLOCK_BYTES_EqualToLeaEngineBLOCKSIZE_() throws ReflectiveOperationException {
        final Field field = LeaEngine.class.getDeclaredField("BLOCKSIZE");
        field.setAccessible(true);
        final int actual = LeaConstants.BLOCK_BYTES;
        final int expected = (int) field.get(null);
        assertThat(actual)
                .isEqualTo(expected);
    }

    @DisplayName("BLOCK_BYTES == BLOCK_SIZE / 8")
    @Test
    void BLOCK_BYTES_BLOCK_SIZEDividedBy8_() {
        assertThat(LeaConstants.BLOCK_BYTES) // NOSONAR
                .isEqualTo(LeaConstants.BLOCK_SIZE / Byte.SIZE);
    }

    @Test
    void KEY_SIZES__() {
        assertThat(LeaConstants.KEY_SIZES)
                .isNotEmpty()
                .doesNotContainNull()
                .allSatisfy(v -> {
                    assertThat(v % Byte.SIZE).isZero();
                });
    }
}