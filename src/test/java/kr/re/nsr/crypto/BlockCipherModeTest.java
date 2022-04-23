package kr.re.nsr.crypto;

import lombok.extern.slf4j.Slf4j;

import java.util.Objects;

@Slf4j
abstract class BlockCipherModeTest<T extends BlockCipherMode> {

    BlockCipherModeTest(final Class<T> cipherClass) {
        super();
        this.cipherClass = Objects.requireNonNull(cipherClass, "cipherClass is null");
    }

    protected final Class<T> cipherClass;
}