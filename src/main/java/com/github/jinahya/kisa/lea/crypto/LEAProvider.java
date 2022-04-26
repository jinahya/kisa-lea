package com.github.jinahya.kisa.lea.crypto;

import java.security.Provider;

public class LEAProvider
        extends Provider {

    protected LEAProvider() {
        super("GJ", 0.1d, "info");
    }
}
