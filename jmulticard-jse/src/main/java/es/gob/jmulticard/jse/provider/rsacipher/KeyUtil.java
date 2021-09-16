/*
 * Copyright (c) 2012, 2014, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package es.gob.jmulticard.jse.provider.rsacipher;

import java.security.SecureRandom;

/** Utilidad para claves RSA. */
final class KeyUtil {

    /**
     * Check the format of TLS PreMasterSecret.
     * <P>
     * To avoid vulnerabilities described by section 7.4.7.1, RFC 5246,
     * treating incorrectly formatted message blocks and/or mismatched
     * version numbers in a manner indistinguishable from correctly
     * formatted RSA blocks.
     *
     * RFC 5246 describes the approach as :
     *
     *  1. Generate a string R of 48 random bytes
     *
     *  2. Decrypt the message to recover the plaintext M
     *
     *  3. If the PKCS#1 padding is not correct, or the length of message
     *     M is not exactly 48 bytes:
     *        pre_master_secret = R
     *     else If ClientHello.client_version &lt;= TLS 1.0, and version
     *     number check is explicitly disabled:
     *        premaster secret = M
     *     else If M[0..1] != ClientHello.client_version:
     *        premaster secret = R
     *     else:
     *        premaster secret = M
     *
     * Note that #2 should have completed before the call to this method.
     *
     * @param  clientVersion the version of the TLS protocol by which the
     *         client wishes to communicate during this session
     * @param  serverVersion the negotiated version of the TLS protocol which
     *         contains the lower of that suggested by the client in the client
     *         hello and the highest supported by the server.
     * @param  encoded the encoded key in its "RAW" encoding format
     * @param  isFailOver whether or not the previous decryption of the
     *         encrypted PreMasterSecret message run into problem
     * @return the polished PreMasterSecret key in its "RAW" encoding format
     */
    static byte[] checkTlsPreMasterSecretKey(final int clientVersion,
    		                                 final int serverVersion,
    		                                 final SecureRandom random,
    		                                 final byte[] encoded,
    		                                 final boolean isFailOver) {

        final byte[] replacer = new byte[48];
        (random != null ? random : new SecureRandom()).nextBytes(replacer);

        if (!isFailOver && encoded != null) {
            // check the length
            if (encoded.length != 48) {
                // private, don't need to clone the byte array.
                return replacer;
            }

            final int encodedVersion = (encoded[0] & 0xFF) << 8 | encoded[1] & 0xFF;
            if (clientVersion != encodedVersion && (clientVersion > 0x0301 || serverVersion != encodedVersion)) { // 0x0301: TLSv1
			    return replacer;
			}

        	// Otherwise, For compatibility, we maintain the behavior
		    // that the version in pre_master_secret can be the
		    // negotiated version for TLS v1.0 and SSL v3.0.

            // private, don't need to clone the byte array.
            return encoded;
        }

        // private, don't need to clone the byte array.
        return replacer;
    }

}

