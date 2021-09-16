/*
 * Copyright (c) 2005, 2013, Oracle and/or its affiliates. All rights reserved.
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

import java.security.spec.AlgorithmParameterSpec;

/**
 * Par&aacute;metros para el RSA premaster secret de SSL/TLS.
 *
 * <p>Instances of this class are immutable.
 *
 * @since   1.6
 * @author  Andreas Sterbenz
 */
final class TlsRsaPremasterSecretParameterSpec implements AlgorithmParameterSpec {

    private final int clientVersion;
    private final int serverVersion;

    /**
     * Constructs a new TlsRsaPremasterSecretParameterSpec.
     *
     * @param clientVersion the version of the TLS protocol by which the
     *        client wishes to communicate during this session
     * @param serverVersion the negotiated version of the TLS protocol which
     *        contains the lower of that suggested by the client in the client
     *        hello and the highest supported by the server.
     *
     * @throws IllegalArgumentException if clientVersion or serverVersion are
     *   negative or larger than (2^16 - 1)
     */
    TlsRsaPremasterSecretParameterSpec(final int clientVersion, final int serverVersion) {

        this.clientVersion = checkVersion(clientVersion);
        this.serverVersion = checkVersion(serverVersion);
    }

    /**
     * Returns the version of the TLS protocol by which the client wishes to
     * communicate during this session.
     *
     * @return the version of the TLS protocol in ClientHello message
     */
    int getClientVersion() {
        return this.clientVersion;
    }

    /**
     * Returns the negotiated version of the TLS protocol which contains the
     * lower of that suggested by the client in the client hello and the
     * highest supported by the server.
     *
     * @return the negotiated version of the TLS protocol in ServerHello message
     */
    int getServerVersion() {
        return this.serverVersion;
    }

    private static int checkVersion(final int version) {
        if (version < 0 || version > 0xFFFF) {
            throw new IllegalArgumentException(
        		"La version debe ser un numero entre 0 y 65,535" //$NON-NLS-1$
    		);
        }
        return version;
    }
}
