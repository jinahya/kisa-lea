package kr.re.nsr.crypto.mode;

import kr.re.nsr.crypto.BlockCipherModeAETest;

public abstract class GCMModeTest<T extends GCMMode>
        extends BlockCipherModeAETest<T> {

    protected GCMModeTest(final Class<T> modeClass) {
        super(modeClass);
    }
}