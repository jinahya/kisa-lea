package com.github.jinahya.kisa.lea;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LeaConstantsTest {

    @Test
    void BLOCK_SIZE__() {
        assertThat(LeaConstants.BLOCK_SIZE) // NOSONAR
                .satisfies(v -> {
                    assertThat(v % Byte.SIZE).isZero();
                });
    }

    @Test
    void BLOCK_BYTES__() {
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