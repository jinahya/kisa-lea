package kr.re.nsr.crypto.mode;

import kr.re.nsr.crypto.BlockCipherModeBlockTest;

public abstract class CBCModeTest<T extends CBCMode>
        extends BlockCipherModeBlockTest<T> {

    protected CBCModeTest(final Class<T> modeClass) {
        super(modeClass);
    }
}