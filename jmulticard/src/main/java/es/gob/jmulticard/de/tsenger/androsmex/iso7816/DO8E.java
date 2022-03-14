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
package es.gob.jmulticard.de.tsenger.androsmex.iso7816;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

/** Checksum.
 * <code>| 0x8E | 0x08 | Checksum (8 octetos) |</code>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Tobias Senger (tobias@t-senger.de). */
final class DO8E {

	private static final byte TAG = (byte) 0x8e;
	private final Tlv tlv;

	DO8E(final byte[] checksumOrEncoded) throws SecureMessagingException {
		if (checksumOrEncoded == null) {
			throw new IllegalArgumentException(
				"El checksum para el DO8E no puede ser nulo" //$NON-NLS-1$
			);
		}
		if (checksumOrEncoded.length == 10) {
			try {
				this.tlv = new Tlv(checksumOrEncoded);
			}
			catch (final TlvException e) {
				throw new SecureMessagingException(
					"Los datos proporcionados no son un TLV valido", e //$NON-NLS-1$
				);
			}
			if (TAG != this.tlv.getTag()) {
				throw new SecureMessagingException(
					"Los datos proporcionados para el DO8E conforman un TLV con una etiqueta desconocida: " + //$NON-NLS-1$
						HexUtils.hexify(new byte[] { this.tlv.getTag() }, false)
				);
			}
		}
		else {
			this.tlv = new Tlv(TAG, checksumOrEncoded);
		}
	}

	byte[] getEncoded() {
		return this.tlv.getBytes();
	}

	byte[] getData() {
		return this.tlv.getValue();
	}
}
