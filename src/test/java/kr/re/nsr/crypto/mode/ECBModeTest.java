package kr.re.nsr.crypto.mode;

import kr.re.nsr.crypto.BlockCipherModeBlockTest;

public abstract class ECBModeTest<T extends ECBMode>
        extends BlockCipherModeBlockTest<T> {

    protected ECBModeTest(final Class<T> modeClass) {
        super(modeClass);
    }
}