package com.github.jinahya.kisa.lea;

import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.BlockCipherMode;
import kr.re.nsr.crypto.BlockCipherModeBlock;
import kr.re.nsr.crypto.BlockCipherModeStream;
import kr.re.nsr.crypto.padding.PKCS5Padding;
import kr.re.nsr.crypto.symm.LEA;

import java.lang.reflect.Constructor;
import java.security.NoSuchAlgorithmException;

class ModeFactory {

    private static <T extends BlockCipherMode> T newInstance(final Class<T> type, final String name)
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

    private static <T extends BlockCipherMode> T init(final T cipher, final BlockCipher.Mode mode, final byte[] key,
                                                      final byte[] iv) {
        if (key == null) {
            throw new NullPointerException("key is null");
        }
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("invalid key");
        }
        if (iv != null && iv.length != LeaConstants.BLOCK_BYTES) {
            throw new IllegalArgumentException("invalid iv");
        }
        if (iv == null) {
            cipher.init(mode, key);
        } else {
            cipher.init(mode, key, iv);
        }
        return cipher;
    }

    public static final class Block
            extends ModeFactory {

        private static BlockCipherModeBlock newInstance(final String name) throws NoSuchAlgorithmException {
            return ModeFactory.newInstance(BlockCipherModeBlock.class, name);
        }

        private static BlockCipherModeBlock newInstance(final String name, final BlockCipher.Mode mode, final byte[] key,
                                                        final byte[] iv)
                throws NoSuchAlgorithmException {
            return init(newInstance(name), mode, key, iv);
        }

        private static BlockCipherMode ECB(final BlockCipher.Mode mode, final byte[] key, final boolean padding) {
            final BlockCipherMode cipher;
            final String name = "ECB";
            try {
                cipher = newInstance(name, mode, key, null);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new RuntimeException(nsae);
            }
            if (padding) {
                cipher.setPadding(new PKCS5Padding(LeaConstants.BLOCK_BYTES));
            }
            return cipher;
        }

        public static BlockCipherMode ECB_PKCS5Padding(final BlockCipher.Mode mode, final byte[] key) {
            return ECB(mode, key, true);
        }

        public static BlockCipherMode ECB_NoPadding(final BlockCipher.Mode mode, final byte[] key) {
            return ECB(mode, key, true);
        }

        private static BlockCipherMode CBC(final BlockCipher.Mode mode, final byte[] key, final byte[] iv,
                                           final boolean padding) {
            final BlockCipherMode cipher;
            final String name = "CBC";
            try {
                cipher = newInstance(name, mode, key, iv);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new RuntimeException(nsae);
            }
            if (padding) {
                cipher.setPadding(new PKCS5Padding(LeaConstants.BLOCK_BYTES));
            }
            return cipher;
        }

        public static BlockCipherMode CBC_PKCK5Padding(final BlockCipher.Mode mode, final byte[] key, final byte[] iv) {
            return CBC(mode, key, iv, true);
        }

        public static BlockCipherMode CBC_NoPadding(final BlockCipher.Mode mode, final byte[] key, final byte[] iv) {
            return CBC(mode, key, iv, false);
        }

        private Block() {
            throw new AssertionError("instantiation is not allowed");
        }
    }

    public static final class Stream
            extends ModeFactory {

        private static BlockCipherModeStream newInstance(final String name) throws NoSuchAlgorithmException {
            return ModeFactory.newInstance(BlockCipherModeStream.class, name);
        }

        private static BlockCipherModeStream newInstance(final String name, final BlockCipher.Mode mode, final byte[] key,
                                                         final byte[] iv)
                throws NoSuchAlgorithmException {
            return init(newInstance(name), mode, key, iv);
        }

        private static BlockCipherMode CTR(final BlockCipher.Mode mode, final byte[] key, final byte[] iv) {
            final BlockCipherMode cipher;
            final String name = "CTR";
            try {
                cipher = newInstance(name, mode, key, iv);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new RuntimeException(nsae);
            }
            return cipher;
        }

        public static BlockCipherMode CTR_NoPadding(final BlockCipher.Mode mode, final byte[] key, final byte[] iv) {
            return CTR(mode, key, iv);
        }

        private static BlockCipherMode CFB(final BlockCipher.Mode mode, final byte[] key, final byte[] iv) {
            final BlockCipherMode cipher;
            final String name = "CFB";
            try {
                cipher = newInstance(name, mode, key, iv);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new RuntimeException(nsae);
            }
            return cipher;
        }

        public static BlockCipherMode CFB_NoPadding(final BlockCipher.Mode mode, final byte[] key, final byte[] iv) {
            return CFB(mode, key, iv);
        }

        private static BlockCipherMode OFB(final BlockCipher.Mode mode, final byte[] key, final byte[] iv) {
            final BlockCipherMode cipher;
            final String name = "OFB";
            try {
                cipher = newInstance(name, mode, key, iv);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new RuntimeException(nsae);
            }
            return cipher;
        }

        public static BlockCipherMode OFB_NoPadding(final BlockCipher.Mode mode, final byte[] key, final byte[] iv) {
            return OFB(mode, key, iv);
        }

        private Stream() {
            throw new AssertionError("instantiation is not allowed");
        }
    }

    private ModeFactory() {
        throw new AssertionError("instantiation is not allowed");
    }
}
