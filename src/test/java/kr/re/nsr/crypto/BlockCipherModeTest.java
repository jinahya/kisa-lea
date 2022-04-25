package kr.re.nsr.crypto;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.util.Objects;

@Slf4j
abstract class BlockCipherModeTest<T extends BlockCipherMode> {

    protected BlockCipherModeTest(final Class<T> modeClass) {
        super();
        this.modeClass = Objects.requireNonNull(modeClass, "modeClass is null");
    }

    protected T modeInstance() {
        try {
            final var constructor = modeClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            return constructor.newInstance();
        } catch (final ReflectiveOperationException roe) {
            throw new RuntimeException(roe);
        }
    }

    @Test
    void getAlgorithmName__() {
        final var algorithmName = modeInstance().getAlgorithmName();
    }

    protected final Class<T> modeClass;
}