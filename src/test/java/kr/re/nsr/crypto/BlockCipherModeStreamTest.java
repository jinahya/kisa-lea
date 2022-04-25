package kr.re.nsr.crypto;

public abstract class BlockCipherModeStreamTest<T extends BlockCipherModeStream>
        extends BlockCipherModeTest<T> {

    protected BlockCipherModeStreamTest(final Class<T> modeClass) {
        super(modeClass);
    }
}