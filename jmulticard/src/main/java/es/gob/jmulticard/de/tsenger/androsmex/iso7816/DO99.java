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

import java.io.IOException;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;

/**
 *
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
final class DO99 {

	private byte[] data = null;
	private DERTaggedObject to = null;

	DO99() {}

	DO99(byte[] le) {
		this.data = le.clone();
		this.to = new DERTaggedObject(false, 0x19, new DEROctetString(le));
	}

	void fromByteArray(byte[] encodedData) throws SecureMessagingException {
		final ASN1InputStream asn1in = new ASN1InputStream(encodedData);
		try {
			this.to = (DERTaggedObject) asn1in.readObject();
			asn1in.close();
		}
		catch (final IOException e) {
			throw new SecureMessagingException(e);
		}
		finally {
			try {
				asn1in.close();
			}
			catch (final IOException e) {
				throw new SecureMessagingException(e);
			}
		}

		final DEROctetString ocs = (DEROctetString) this.to.getObject();
		this.data = ocs.getOctets();

	}

	byte[] getEncoded() throws SecureMessagingException {
    	try {
			return this.to.getEncoded();
		} catch (final IOException e) {
			throw new SecureMessagingException(e);
		}
    }

	byte[] getData() {
		return this.data;
	}
}
