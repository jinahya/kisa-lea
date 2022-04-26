package com.github.jinahya.kisa.lea.crypto;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import java.lang.reflect.Constructor;
import java.security.Provider;

public class LEACipher {

    Cipher a(final String transformation) throws Exception {
        final Constructor<Cipher> constructor = Cipher.class.getDeclaredConstructor(CipherSpi.class, Provider.class, String.class);
        constructor.setAccessible(true);
        return constructor.newInstance(new LEACipherSpi(), new LEAProvider(), transformation);
    }
}
