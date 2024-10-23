/*
 * Copyright (c) 1999, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package es.gob.jmulticard.jse.provider.rsacipher;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/** Clase de utilidad para la construcci&oacute;n de objetos que encapsulan
 * claves criptogr&aacute;ficas.
 * @author Sharon Liu. */
final class ConstructKeys {

	private ConstructKeys() {
		// Vacio
	}

    /** Construye una clave p&uacute;blica a partir de su codificaci&oacute;n.
     * @param encodedKey Codificaci&oacute;n de la clave p&uacute;blica.
     * @param encodedKeyAlgorithm Nombre del algoritmo de codificaci&oacute;n.
     * @return Clave p&uacute;blica constru&iacute;da a partir de la codificaci&oacute;n
     *         proporcionada. */
    private static PublicKey constructPublicKey(final byte[] encodedKey,
    		                                    final String encodedKeyAlgorithm) throws InvalidKeyException,
                                                                                         NoSuchAlgorithmException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(encodedKeyAlgorithm);
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            return keyFactory.generatePublic(keySpec);
        }
        catch (final InvalidKeySpecException ikse) {
            throw new InvalidKeyException("No se ha podido construir la clave publica: " + ikse, ikse); //$NON-NLS-1$
        }
    }

    /** Construye una clave privada a partir de su codificaci&oacute;n.
     * @param encodedKey Codificaci&oacute;n de la clave privada.
     * @param encodedKeyAlgorithm Nombre del algoritmo de codificaci&oacute;n.
     * @return Clave privada constru&iacute;da a partir de la codificaci&oacute;n
     *         proporcionada. */
    private static PrivateKey constructPrivateKey(final byte[] encodedKey,
    		                                      final String encodedKeyAlgorithm) throws InvalidKeyException,
                                                                                           NoSuchAlgorithmException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(encodedKeyAlgorithm);
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
            return keyFactory.generatePrivate(keySpec);
        }
        catch (final InvalidKeySpecException ikse) {
        	throw new InvalidKeyException("No se ha podido construir la clave privada: " + ikse, ikse); //$NON-NLS-1$
        }
    }

    /** Construye una clave sim&eacute;trica a partir de su codificaci&oacute;n.
     * @param encodedKey Codificaci&oacute;n de la clave sim&eacute;trica.
     * @param encodedKeyAlgorithm Nombre del algoritmo de codificaci&oacute;n.
     * @return Clave sim&eacute;trica constru&iacute;da a partir de la codificaci&oacute;n
     *         proporcionada. */
    private static SecretKey constructSecretKey(final byte[] encodedKey, final String encodedKeyAlgorithm) {
        return new SecretKeySpec(encodedKey, encodedKeyAlgorithm);
    }

    static Key constructKey(final byte[] encoding,
    		                final String keyAlgorithm,
    		                final int keyType) throws InvalidKeyException,
                                                      NoSuchAlgorithmException {
        switch (keyType) {
	        case Cipher.SECRET_KEY:
	            return ConstructKeys.constructSecretKey(encoding, keyAlgorithm);
	        case Cipher.PRIVATE_KEY:
	            return ConstructKeys.constructPrivateKey(encoding, keyAlgorithm);
	        case Cipher.PUBLIC_KEY:
	            return ConstructKeys.constructPublicKey(encoding, keyAlgorithm);
			default:
				throw new InvalidKeyException(
					"Tipo de clave no soportada: " + keyType //$NON-NLS-1$
				);
        }
    }
}
