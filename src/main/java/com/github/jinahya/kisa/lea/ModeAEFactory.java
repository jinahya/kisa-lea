package com.github.jinahya.kisa.lea;

import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.BlockCipherModeAE;
import kr.re.nsr.crypto.symm.LEA;

import java.lang.reflect.Constructor;
import java.security.NoSuchAlgorithmException;

class ModeAEFactory {

    private static <T extends BlockCipherModeAE> T newInstance(final Class<T> type, final String name)
            throws NoSuchAlgorithmException {
        if (type == null) {
            throw new NullPointerException("type is null");
        }
        if (name == null) {
            throw new NullPointerException("name is null");
        }
        for (final Class<?> clazz : LEA.class.getDeclaredClasses()) {
            if (!name.equals(clazz.getSimpleName())) {
                continue;
            }
            if (!type.isAssignableFrom(clazz)) {
                continue;
            }
            final Constructor<? extends T> constructor;
            try {
                constructor = clazz.asSubclass(type).getConstructor();
            } catch (final NoSuchMethodException nsme) {
                throw new RuntimeException(nsme);
            }
            try {
                return constructor.newInstance();
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }
        throw new NoSuchAlgorithmException("unknown name: " + name);
    }

//    private static <T extends BlockCipherModeAE> T newInstance(final String name) throws NoSuchAlgorithmException {
//        return newInstance(BlockCipherModeAE.class, name);
//    }

    private static <T extends BlockCipherModeAE> T init(final T cipher, final BlockCipher.Mode mode, final byte[] key,
                                                        final int tLen, final byte[] src, final byte[] aad) {
        if (key == null) {
            throw new NullPointerException("key is null");
        }
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("invalid key");
        }
        if (src != null && src.length != LeaConstants.BLOCK_BYTES) {
            throw new IllegalArgumentException("invalid src");
        }
        cipher.init(mode, key, src, tLen);
        cipher.updateAAD(aad);
        return cipher;
    }

    private ModeAEFactory() {
        throw new AssertionError("instantiation is not allowed");
    }
}
