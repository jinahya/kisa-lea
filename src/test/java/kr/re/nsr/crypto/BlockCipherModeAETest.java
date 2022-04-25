package kr.re.nsr.crypto;

import kr.re.nsr.crypto.engine.LeaEngine;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;

@Slf4j
public abstract class BlockCipherModeAETest<T extends BlockCipherModeAE> {

    protected BlockCipherModeAETest(final Class<T> modeClass) {
        super();
        this.modeClass = Objects.requireNonNull(modeClass, "modeClass is null");
    }

    protected T modeInstance(final BlockCipher cipher) {
        Objects.requireNonNull(cipher, "cipher is null");
        try {
            final var constructor = modeClass.getDeclaredConstructor(BlockCipher.class);
            constructor.setAccessible(true);
            return constructor.newInstance(cipher);
        } catch (final ReflectiveOperationException roe) {
            throw new RuntimeException(roe);
        }
    }

    protected T modeInstance() {
        return modeInstance(new LeaEngine());
    }

    protected final Class<T> modeClass;
}