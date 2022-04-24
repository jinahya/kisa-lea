package kr.re.nsr.crypto.symm;

import kr.re.nsr.crypto.BlockCipherModeBlock;
import kr.re.nsr.crypto.BlockCipherModeStream;

import java.lang.reflect.Constructor;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.IntStream;
import java.util.stream.Stream;

final class LeaTests {

    private static Stream<Class<?>> blockCipherModeBlockClasses() {
        return Arrays.stream(LEA.class.getDeclaredClasses())
                .filter(BlockCipherModeBlock.class::isAssignableFrom);
    }

    public static void acceptBlockCipherModeBlockInstances(final BiConsumer<? super Class<?>, ? super BlockCipherModeBlock> consumer) {
        Objects.requireNonNull(consumer, "consumer is null");
        blockCipherModeBlockClasses().forEach(c -> {
            try {
                final Constructor<?> constructor = c.getConstructor();
                final BlockCipherModeBlock instance = (BlockCipherModeBlock) constructor.newInstance();
                consumer.accept(c, instance);
            } catch (final ReflectiveOperationException roe) {
                throw new RuntimeException(roe);
            }
        });
    }

    private static Stream<Class<?>> blockCipherModeStreamClasses() {
        return Arrays.stream(LEA.class.getDeclaredClasses())
                .filter(BlockCipherModeStream.class::isAssignableFrom);
    }

    public static void acceptBlockCipherModeStreamInstances(final Consumer<? super BlockCipherModeStream> consumer) {
        Objects.requireNonNull(consumer, "consumer is null");
        blockCipherModeBlockClasses().forEach(c -> {
            try {
                final Constructor<?> constructor = c.getConstructor();
                final BlockCipherModeStream instance = (BlockCipherModeStream) constructor.newInstance();
                consumer.accept(instance);
            } catch (final ReflectiveOperationException roe) {
                throw new RuntimeException(roe);
            }
        });
    }

    public static void acceptKeys(final Consumer<? super byte[]> consumer) {
        Objects.requireNonNull(consumer, "consumer is null");
        for (final var size : new int[]{128, 192, 256}) {
            final var key = new byte[size / Byte.SIZE];
            try {
                SecureRandom.getInstanceStrong().nextBytes(key);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new RuntimeException(nsae);
            }
            consumer.accept(key);
        }
    }

    public static IntStream keySizeStream() {
        return IntStream.of(128, 192, 256);
    }

    public static Stream<byte[]> keyBytesStream() {
        return keySizeStream().mapToObj(size -> {
            final var key = new byte[size / Byte.SIZE];
            try {
                SecureRandom.getInstanceStrong().nextBytes(key);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new RuntimeException(nsae);
            }
            return key;
        });
    }

    private LeaTests() {
        throw new AssertionError("instantiation is not allowed");
    }
}