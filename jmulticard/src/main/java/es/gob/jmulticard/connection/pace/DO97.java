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

/** <i>Payload</i> de respuesta.
 * <code>| 0x97 | L | Longitud (L octetos) |</code>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Tobias Senger (tobias@t-senger.de). */
final class DO97 {

    private static final byte TAG = (byte) 0x97;
    private final Tlv tlv;

	DO97(final int le) {
		tlv = new Tlv(TAG, new byte[] { (byte) le });
	}

	byte[] getEncoded() {
		return tlv.getBytes();
    }
}
