package kr.re.nsr.crypto;

abstract class BlockCipherModeBlockTest<T extends BlockCipherModeBlock>
        extends BlockCipherModeTest<T> {

    BlockCipherModeBlockTest(final Class<T> cipherClass) {
        super(cipherClass);
    }
}