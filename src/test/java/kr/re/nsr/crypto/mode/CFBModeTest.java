package kr.re.nsr.crypto.mode;

import kr.re.nsr.crypto.BlockCipherModeStreamTest;

public abstract class CFBModeTest<T extends CFBMode>
        extends BlockCipherModeStreamTest<T> {

    protected CFBModeTest(final Class<T> modeClass) {
        super(modeClass);
    }
}