package kr.re.nsr.crypto.mode;

import kr.re.nsr.crypto.BlockCipherModeAETest;

public abstract class CCMModeTest<T extends CCMMode>
        extends BlockCipherModeAETest<T> {

    protected CCMModeTest(final Class<T> modeClass) {
        super(modeClass);
    }
}