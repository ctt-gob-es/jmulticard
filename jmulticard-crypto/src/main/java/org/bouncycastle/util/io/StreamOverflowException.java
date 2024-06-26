package org.bouncycastle.util.io;

import java.io.IOException;

/**
 * Exception thrown when too much data is written to an InputStream
 */
public class StreamOverflowException extends IOException {
    public StreamOverflowException(final String msg) {
        super(msg);
    }
}
