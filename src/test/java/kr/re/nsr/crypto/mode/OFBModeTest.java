package kr.re.nsr.crypto.mode;

import kr.re.nsr.crypto.BlockCipherModeStreamTest;

public abstract class OFBModeTest<T extends OFBMode>
        extends BlockCipherModeStreamTest<T> {

    protected OFBModeTest(final Class<T> modeClass) {
        super(modeClass);
    }
}