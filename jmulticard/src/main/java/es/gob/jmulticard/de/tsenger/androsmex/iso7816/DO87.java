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
 * Par&aacute;metros de comando
 *
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
final class DO87 {

    private byte[] value_ = null;
    private byte[] data = null;
    private DERTaggedObject to = null;

    DO87() {}

	DO87(byte[] data) {
		this.data = data.clone();
		this.value_ = addOne(data);
		this.to = new DERTaggedObject(false, 7, new DEROctetString(this.value_));
	}

	private static byte[] addOne(byte[] data) {
		final byte[] ret = new byte[data.length+1];
		System.arraycopy(data, 0, ret, 1, data.length);
		ret[0] = 1;
		return ret;
	}

	private static byte[] removeOne(byte[] value) {
		final byte[] ret = new byte[value.length-1];
		System.arraycopy(value, 1, ret, 0, ret.length);
		return ret;
	}

	void fromByteArray(byte[] encodedData) throws SecureMessagingException {
    	final ASN1InputStream asn1in = new ASN1InputStream(encodedData);
    	try {
			this.to = (DERTaggedObject)asn1in.readObject();
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
		this.value_ = ocs.getOctets();
		this.data = removeOne(this.value_);
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
