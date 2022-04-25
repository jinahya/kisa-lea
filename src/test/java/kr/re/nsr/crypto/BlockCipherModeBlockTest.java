package kr.re.nsr.crypto;

public abstract class BlockCipherModeBlockTest<T extends BlockCipherModeBlock>
        extends BlockCipherModeTest<T> {

    protected BlockCipherModeBlockTest(final Class<T> modeClass) {
        super(modeClass);
    }
}