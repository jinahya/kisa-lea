package com.github.jinahya.kisa.lea.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;

class LEACipherTest {

    @Test
    void a() throws Exception {
        Cipher cipher = new LEACipher().a("aaa");
    }
}