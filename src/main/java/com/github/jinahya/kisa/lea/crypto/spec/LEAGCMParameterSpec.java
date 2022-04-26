package com.github.jinahya.kisa.lea.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;

public class LEAGCMParameterSpec
        implements AlgorithmParameterSpec {

    public static LEAGCMParameterSpec of(final byte[] nonce, final int taglen) {
        return new LEAGCMParameterSpec(taglen, nonce);
    }

    public LEAGCMParameterSpec(final int tLen, byte[] src) {
        super();
        if (tLen < 4 || tLen > 16) {
            throw new IllegalArgumentException("invalid tLen(" + tLen + "); should be [4..16]");
        }
        if (src == null) {
            throw new NullPointerException("src is null");
        }
        if (src.length < 1) {
            throw new IllegalArgumentException("src.length(" + src.length + ") < 1");
        }
        this.tLen = tLen;
        this.src = src;
    }

    public byte[] getIV() {
        final byte[] iv = new byte[src.length];
        System.arraycopy(src, 0, iv, 0, iv.length);
        return iv;
    }

    public int getTLen() {
        return tLen;
    }

    private final int tLen;

    private final byte[] src;
}
