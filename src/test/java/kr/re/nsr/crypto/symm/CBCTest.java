package kr.re.nsr.crypto.symm;

import kr.re.nsr.crypto.mode.CBCMode;
import kr.re.nsr.crypto.mode.CBCModeTest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class CBCTest
        extends CBCModeTest<LEA.CBC> {

    CBCTest() {
        super(LEA.CBC.class);
    }

    @Test
    void reset_NullPointerException_BeforeInit() throws ReflectiveOperationException {
        final var modeInstance = modeInstance();
        {
            final var field = CBCMode.class.getDeclaredField("iv");
            field.setAccessible(true);
            final var value = field.get(modeInstance);
            assertThat(value).isNull();
        }
        assertThatThrownBy(modeInstance::reset)
                .isInstanceOf(NullPointerException.class);
    }
}