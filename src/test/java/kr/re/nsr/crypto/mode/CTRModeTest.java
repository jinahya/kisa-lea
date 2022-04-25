package kr.re.nsr.crypto.mode;

import kr.re.nsr.crypto.BlockCipherModeStreamTest;

public abstract class CTRModeTest<T extends CTRMode>
        extends BlockCipherModeStreamTest<T> {

    protected CTRModeTest(final Class<T> modeClass) {
        super(modeClass);
    }
}