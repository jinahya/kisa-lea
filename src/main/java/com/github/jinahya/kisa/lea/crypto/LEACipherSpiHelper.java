package com.github.jinahya.kisa.lea.crypto;

import com.github.jinahya.kisa.lea.LeaConstants;
import com.github.jinahya.kisa.lea.crypto.spec.LEAGCMParameterSpec;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.Padding;
import kr.re.nsr.crypto.engine.LeaEngine;
import kr.re.nsr.crypto.padding.PKCS5Padding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

final class LEACipherSpiHelper {

    private static BlockCipher.Mode mode(final int opmode) {
        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
            throw new IllegalArgumentException("unsupported opmode: " + opmode);
        }
        return opmode == Cipher.ENCRYPT_MODE ? BlockCipher.Mode.ENCRYPT : BlockCipher.Mode.DECRYPT;
    }

    private static byte[] mk(final Key key) throws InvalidKeyException {
        final byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("unable to get encoded from " + key);
        }
        final int length = encoded.length;
        if (length != 16 && length != 24 && length != 32) {
            throw new InvalidKeyException("invalid key length: " + length);
        }
        return encoded;
    }

    private static Padding padding(final String padding) throws NoSuchPaddingException {
        if (padding.equals(LeaConstants.PADDING_PKCS5_PADDING)) {
            return new PKCS5Padding(16);
        }
        if (padding.equals(LeaConstants.PADDING_NO_PADDING)) {
            return null;
        }
        throw new NoSuchPaddingException("unsupported padding: " + padding);
    }

    static byte[] engineDoFinal(final Object engine, byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        for (Class<?> c = engine.getClass(); c != null; c = c.getSuperclass()) {
            final Method method;
            try {
                method = c.getMethod("doFinal", byte[].class);
                try {
                    final byte[] msg = new byte[inputLen];
                    System.arraycopy(input, inputOffset, msg, 0, msg.length);
                    return (byte[]) method.invoke(engine, msg);
                } catch (final Exception e) {
                    throw new RuntimeException("unable to invoke " + method + " on " + engine, e);
                }
            } catch (final NoSuchMethodException nsme) {
                continue;
            }
        }
        throw new RuntimeException("unable to find doFinal([B) from " + engine);
    }

    static int engineDoFinal(final Object engine, final byte[] input, final int inputOffset, final int inputLen,
                             final byte[] output, final int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }

    static int engineDoFinal(final Object engine, final ByteBuffer input, final ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }

    static int engineGetBlockSize(final Object engine) {
        try {
            final Field field = LeaEngine.class.getDeclaredField("BLOCKSIZE");
            field.setAccessible(true);
            try {
                return field.getInt(null);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        } catch (final NoSuchFieldException nsfe) {
            throw new RuntimeException(nsfe);
        }
    }

    static byte[] engineGetIV(final Object engine) throws IllegalAccessException {
        for (Class<?> c = engine.getClass(); c != null; c = c.getSuperclass()) {
            Field field;
            try {
                field = c.getDeclaredField("iv");
            } catch (final NoSuchFieldException nsfe) {
                continue;
            }
            assert field.getType() == byte[].class;
            field.setAccessible(true);
            return ((byte[]) field.get(engine)).clone();
        }
        return null;
    }

    static int engineGetKeySize(final Key key) throws InvalidKeyException {
        return mk(key).length << 3;
    }

    static int engineGetOutputSize(final Object engine, final int inputLen) {
        for (Class<?> c = engine.getClass(); c != null; c = c.getSuperclass()) {
            final Method method;
            try {
                method = c.getMethod("getOutputSize", int.class);
                try {
                    return (Integer) method.invoke(engine, inputLen);
                } catch (final Exception e) {
                    throw new RuntimeException("failed to invoke " + method + " on " + engine + " with " + inputLen, e);
                }
            } catch (final NoSuchMethodException nsme) {
                continue;
            }
        }
        throw new RuntimeException("unable to find getOutputSize()I from " + engine);
    }

    static void engineInit(final Object engine, final int opmode, final Key key, final SecureRandom random)
            throws InvalidKeyException {
        for (Class<?> c = engine.getClass(); c != null; c = c.getSuperclass()) {
            final Method method;
            try {
                method = c.getMethod("init", BlockCipher.Mode.class, byte[].class);
            } catch (final NoSuchMethodException nsme) {
                continue;
            }
            try {
                method.invoke(engine, mode(opmode), mk(key));
                return;
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }
        throw new RuntimeException("failed to init " + engine + " with " + opmode + ", " + key + ", and " + random);
    }

    static void engineInit(final Object engine, final int opmode, final Key key,
                           final AlgorithmParameterSpec params, final SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params instanceof IvParameterSpec) {
            for (Class<?> c = engine.getClass(); c != null; c = c.getSuperclass()) {
                final Method method;
                try {
                    method = c.getMethod("init", BlockCipher.Mode.class, byte[].class, byte[].class);
                } catch (final NoSuchMethodException nsme) {
                    continue;
                }
                method.setAccessible(true);
                try {
                    method.invoke(engine, mode(opmode), mk(key), ((IvParameterSpec) params).getIV());
                    return;
                } catch (final Exception e) {
                    throw new RuntimeException("failed to invoke " + method + " on " + engine + " with " + opmode + ", "
                                               + key + ", " + params + ", and " + random, e);
                }
            }
            throw new RuntimeException("no init(Mode, [B, [B, I) method found on " + engine);
        }
        if (params instanceof LEAGCMParameterSpec) {
            for (Class<?> c = engine.getClass(); c != null; c = c.getSuperclass()) {
                final Method method;
                try {
                    method = c.getMethod("init", BlockCipher.Mode.class, byte[].class, byte[].class, int.class);
                } catch (final NoSuchMethodException nsme) {
                    continue;
                }
                method.setAccessible(true);
                try {
                    final LEAGCMParameterSpec spec = (LEAGCMParameterSpec) params;
                    method.invoke(engine, mode(opmode), mk(key), spec.getIV(), spec.getTLen());
                    return;
                } catch (final Exception e) {
                    throw new RuntimeException("failed to invoke " + method + " on " + engine + " with " + opmode + ", "
                                               + key + ", " + params + ", and " + random, e);
                }
            }
            throw new RuntimeException("no init(Mode, [B, [B, I) method found on " + engine);
        }
        throw new InvalidAlgorithmParameterException("unsupported algorithm parameter: " + params);
    }

    static void engineInit(final Object engine, final int opmode, final Key key, final AlgorithmParameters params,
                           final SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("unsupported");
    }

    static void engineSetPadding(final Object engine, final String padding) throws NoSuchPaddingException {
        final Padding p = padding(padding);
        if (p == null) {
            return;
        }
        for (Class<?> c = engine.getClass(); c != null; c = c.getSuperclass()) {
            final Method method;
            try {
                method = c.getMethod("setPadding", Padding.class);
            } catch (final NoSuchMethodException nsme) {
                continue;
            }
            try {
                method.invoke(engine, padding);
            } catch (final Exception e) {
                throw new RuntimeException("failed to invoke " + method + " on " + engine + " with " + padding, e);
            }
        }
        throw new RuntimeException("unable to find setPadding(Padding) method from " + engine);
    }

    static byte[] engineUpdate(final Object engine, byte[] input, int inputOffset, int inputLen) {
        for (Class<?> c = engine.getClass(); c != null; c = c.getSuperclass()) {
            final Method method;
            try {
                method = c.getMethod("update", byte[].class);
            } catch (final NoSuchMethodException nsme) {
                continue;
            }
            final byte[] msg = new byte[inputLen];
            System.arraycopy(input, inputOffset, msg, 0, msg.length);
            try {
                return (byte[]) method.invoke(engine, msg);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }
        throw new RuntimeException("unable to find update([B)[B method from " + engine);
    }

    static void engineUpdateAAD(final Object engine, final byte[] src, final int offset, final int len) {
        for (Class<?> c = engine.getClass(); c != null; c = c.getSuperclass()) {
            final Method method;
            try {
                method = c.getMethod("updateAAD", byte[].class);
            } catch (final NoSuchMethodException nsme) {
                continue;
            }
            final byte[] aad = new byte[len];
            System.arraycopy(src, offset, aad, 0, aad.length);
            try {
                method.invoke(engine, aad);
                return;
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }
        throw new UnsupportedOperationException("unable to find updateAAD([B) method from " + engine);
    }

    private LEACipherSpiHelper() {
        throw new AssertionError("instantiation is not allowed");
    }
}
