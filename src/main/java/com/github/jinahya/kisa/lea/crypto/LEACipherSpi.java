package com.github.jinahya.kisa.lea.crypto;

import com.github.jinahya.kisa.lea.LEAConstants;
import kr.re.nsr.crypto.symm.LEA;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

class LEACipherSpi
        extends CipherSpi {

    LEACipherSpi() {
        super();
    }

    // --------------------------------------------------------------------------------------------------- engineDoFinal
    @Override
    protected byte[] engineDoFinal(final byte[] input, final int inputOffset, final int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        return LEACipherSpiHelper.engineDoFinal(engine(true), input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
                                final int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        final byte[] output_ = engineDoFinal(input, inputOffset, inputLen);
        if (output_.length > output.length - outputOffset) {
            throw new ShortBufferException();
        }
        System.arraycopy(output_, 0, output, outputOffset, output_.length);
        return output_.length;
    }

    @Override
    protected int engineGetBlockSize() {
        if (true) {
            return LEAConstants.BLOCK_BYTES;
        }
        return LEACipherSpiHelper.engineGetBlockSize(engine(false));
    }

    @Override
    protected byte[] engineGetIV() {
        try {
            return LEACipherSpiHelper.engineGetIV(engine(true));
        } catch (final IllegalAccessException iae) {
            throw new RuntimeException(iae);
        }
    }

    @Override
    protected int engineGetKeySize(final Key key) throws InvalidKeyException {
        return LEACipherSpiHelper.engineGetKeySize(key);
    }

    @Override
    protected int engineGetOutputSize(final int inputLen) {
        return LEACipherSpiHelper.engineGetOutputSize(engine(false), inputLen);
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    // ------------------------------------------------------------------------------------------------------ engineInit
    @Override
    protected void engineInit(final int opmode, final Key key, final SecureRandom random)
            throws InvalidKeyException {
        LEACipherSpiHelper.engineInit(engine(false), opmode, key, random);
        initialized = true;
    }

    @Override
    protected void engineInit(final int opmode, final Key key, final AlgorithmParameterSpec params,
                              final SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        LEACipherSpiHelper.engineInit(engine(false), opmode, key, params, random);
        initialized = true;
    }

    @Override
    protected void engineInit(final int opmode, final Key key, final AlgorithmParameters params,
                              final SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        LEACipherSpiHelper.engineInit(engine(false), opmode, key, params, random);
        initialized = true;
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    protected void engineSetMode(final String mode) throws NoSuchAlgorithmException {
        for (final Class<?> clazz : LEA.class.getDeclaredClasses()) {
            if (clazz.getSimpleName().equals(mode)) {
                final Constructor<?> constructor;
                try {
                    constructor = clazz.getConstructor();
                } catch (final NoSuchMethodException nsme) {
                    throw new RuntimeException(nsme);
                }
                constructor.setAccessible(true);
                try {
                    engine = constructor.newInstance();
                } catch (final Exception e) {
                    throw new RuntimeException("failed to instantiate with " + constructor, e);
                }
                initialized = false;
            }
        }
        throw new NoSuchAlgorithmException("unsupported mode: " + mode);
    }

    @Override
    protected void engineSetPadding(final String padding) throws NoSuchPaddingException {
        LEACipherSpiHelper.engineSetPadding(engine(true), padding);
    }

    @Override
    protected Key engineUnwrap(final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        return super.engineUnwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }

    // ---------------------------------------------------------------------------------------------------- engineUpdate
    @Override
    public byte[] engineUpdate(final byte[] input, final int inputOffset, final int inputLen) {
        return LEACipherSpiHelper.engineUpdate(engine(true), input, inputOffset, inputLen);
    }

    @Override
    public int engineUpdate(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
                            final int outputOffset)
            throws ShortBufferException {
        final byte[] output_ = engineUpdate(input, inputOffset, inputLen);
        if (output_.length > output.length - outputOffset) {
            throw new ShortBufferException();
        }
        System.arraycopy(output_, 0, output, outputOffset, output_.length);
        return output_.length;
    }

    @Override
    public int engineUpdate(final ByteBuffer input, final ByteBuffer output) throws ShortBufferException {
        final byte[] output_ = new byte[output.remaining()];
        if (input.hasArray()) {
            final int inputOffset = input.arrayOffset() + input.position();
            final int inputLen = input.remaining();
            final int outputLen = engineUpdate(input.array(), inputOffset, inputLen, output_, 0);
            if (outputLen > output.remaining()) {
                throw new ShortBufferException();
            }
            output.put(output_, 0, outputLen);
            input.position(input.position() + inputLen);
            return outputLen;
        }
        final byte[] input_ = new byte[input.remaining()];
        input.get(input_, 0, input_.length);
        final int outputLen = engineUpdate(input_, 0, input_.length, output_, 0);
        if (outputLen > output.remaining()) {
            input.position(input.position() - input_.length);
            throw new ShortBufferException();
        }
        output.put(output_, 0, outputLen);
        return outputLen;
    }

    // ------------------------------------------------------------------------------------------------- engineUpdateAAD

    @Override
    protected void engineUpdateAAD(final byte[] src, final int offset, final int len) {
        LEACipherSpiHelper.engineUpdateAAD(engine(true), src, offset, len);
    }

    @Override
    protected void engineUpdateAAD(final ByteBuffer src) {
        if (src.hasArray()) {
            final int len = src.remaining();
            engineUpdateAAD(src.array(), src.arrayOffset() + src.position(), len);
            src.position(src.position() + len);
            return;
        }
        final byte[] src_ = new byte[src.remaining()];
        src.get(src_);
        engineUpdateAAD(src_, 0, src_.length);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private Object engine(final boolean requiredToBeInitialized) {
        if (engine == null) {
            throw new IllegalStateException("engine has not been instantiated yet");
        }
        if (requiredToBeInitialized && !initialized) {
            throw new IllegalStateException("engine has not been initialized yet");
        }
        return engine;
    }

    private void engine(final Object engine) {
        if (engine == null) {
            throw new NullPointerException("engine is null");
        }
        this.engine = engine;
        algorithmParameterSpec = null;
        initialized = false;
    }

    private Object engine;

    private AlgorithmParameterSpec algorithmParameterSpec;

    private boolean initialized = false;
}
