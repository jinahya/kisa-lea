package com.github.jinahya.kisa.lea;

import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

class AeadTestUtilsTest {

    @Test
    void nonceForCcm_LengthIsBetween7And13_() throws NoSuchAlgorithmException {
        final var nonce = AeadTestUtils.nonceForCcm(SecureRandom.getInstanceStrong());
        assertThat(nonce)
                .isNotNull()
                .hasSizeGreaterThanOrEqualTo(7)
                .hasSizeLessThanOrEqualTo(13);
    }

    @Test
    void taglenForCcm_In_() throws NoSuchAlgorithmException {
        final var taglen = AeadTestUtils.taglenForCcm(SecureRandom.getInstanceStrong());
        assertThat(taglen)
                .isIn(4, 6, 8, 10, 12, 14, 16);
    }

    @Test
    void nonceForGcm_NotEmpty_() throws NoSuchAlgorithmException {
        final var nonce = AeadTestUtils.nonceForCcm(SecureRandom.getInstanceStrong());
        assertThat(nonce)
                .isNotNull()
                .isNotEmpty();
    }

    @Test
    void taglenForGcm_Between4And16_() throws NoSuchAlgorithmException {
        final var taglen = AeadTestUtils.taglenForGcm(SecureRandom.getInstanceStrong());
        assertThat(taglen)
                .isGreaterThanOrEqualTo(4)
                .isLessThanOrEqualTo(16);
    }
}
