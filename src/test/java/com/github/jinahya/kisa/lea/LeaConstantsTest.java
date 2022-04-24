package com.github.jinahya.kisa.lea;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LeaConstantsTest {

    @Test
    void BLOCK_SIZE_BLOCK_SIZEDividedBy8_() {
        assertThat(LeaConstants.BLOCK_BYTES)
                .isEqualTo(LeaConstants.BLOCK_SIZE / Byte.SIZE);
    }
}