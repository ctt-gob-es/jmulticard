/**
 *  Copyright 2011, Tobias Senger
 *
 *  This file is part of animamea.
 *
 *  Animamea is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Animamea is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with animamea.  If not, see <http://www.gnu.org/licenses/>.
 */
package es.gob.jmulticard.connection.pace;

import es.gob.jmulticard.asn1.Tlv;

/** Par&aacute;metros de comando.
 * <code>| 0x87 | L | 0x01 | Datos encriptados (L-1 octetos) |</code>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Tobias Senger (tobias@t-senger.de). */
final class DO87 {

	private static final byte TAG = (byte) 0x87;

	private Tlv tlv = null;

    DO87() {
    	// Vacio
    }

	private static byte[] addOne(final byte[] data) {
		final byte[] ret = new byte[data.length+1];
		System.arraycopy(data, 0, ret, 1, data.length);
		ret[0] = 1;
		return ret;
	}

	private static byte[] removeOne(final byte[] value) {
		final byte[] ret = new byte[value.length-1];
		System.arraycopy(value, 1, ret, 0, ret.length);
		return ret;
	}

	DO87(final byte[] encodedOrValue) {
		Tlv tmpTlv;
		if (encodedOrValue == null) {
			throw new IllegalArgumentException(
				"Los datos para construir el DO8E no pueden ser nulos" //$NON-NLS-1$
			);
		}
    	try {
    		tmpTlv = new Tlv(encodedOrValue);
		}
    	catch (final Exception e) {
    		tmpTlv = null;
		}
    	if (tmpTlv != null && (TAG != tmpTlv.getTag() || tmpTlv.getValue()[0] != 0x01)) {
			tmpTlv = null;
		}
    	if (tmpTlv == null) {
    		tmpTlv = new Tlv(TAG, addOne(encodedOrValue));
    	}
    	tlv = tmpTlv;
    }

	byte[] getEncoded() {
    	return tlv.getBytes();
    }

	byte[] getData() {
    	return removeOne(tlv.getValue());
    }
}
