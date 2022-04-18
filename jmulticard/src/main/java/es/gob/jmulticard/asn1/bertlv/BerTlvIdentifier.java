/*
   Copyright Isaac Levin

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package es.gob.jmulticard.asn1.bertlv;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;

import es.gob.jmulticard.HexUtils;

/** Identificador de TLV ASN&#46;1 BER.
 * @author Isaac Levin */
final class BerTlvIdentifier {

    private byte[] value;

    /** Obtiene el valor de la etiqueta (tipo) del TLV.
     * @return Valor de la etiqueta (tipo) del TLV. */
    int getTagValue() {
        if (this.value == null) {
            return 0;
        }
        if (this.value.length == 1) {
            return this.value[0];
        }
        final byte[] tagBytes = new byte[this.value.length - 1];
        System.arraycopy(this.value, 1, tagBytes, 0, this.value.length - 1);
        for (int i = 0; i < tagBytes.length - 1; i++) {
            // Establecemos el octavo bit indicador a false
            tagBytes[i] = (byte) BitManipulationHelper.setBitValue(tagBytes[i], 8, false);
        }
        return new BigInteger(tagBytes).intValue();
    }

    void decode(final ByteArrayInputStream stream) {
        final int tlvIdFirstOctet = stream.read();

        this.value = new byte[] {
            (byte) tlvIdFirstOctet
        };
        // Comprobamos si el id es multi-octeto (los bits del 5 al 1 deben codificarse como 11111)
        final int mask = 31;
        if ((tlvIdFirstOctet & mask) == mask) {
            // Multi-octeto
            do {
                final int tlvIdNextOctet = stream.read();
                boolean lastOctet = false;
                if (!BitManipulationHelper.getBitValue(tlvIdNextOctet, 8)) {
                    lastOctet = true;
                }

                this.value = BitManipulationHelper.mergeArrays(this.value, new byte[] {
                    (byte) tlvIdNextOctet
                });

                if (lastOctet) {
                    break;
                }
            } while (true);
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof BerTlvIdentifier) {
            if (!HexUtils.arrayEquals(this.value, ((BerTlvIdentifier) obj).value)) {
            	return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public int hashCode() {
        return new BigInteger(this.value).intValue();
    }

    @Override
    public String toString() {
        if (this.value == null) {
            return "NULL"; //$NON-NLS-1$
        }
        final StringBuffer buf = new StringBuffer("["); //$NON-NLS-1$
        for (final byte element : this.value) {
            buf.append("0x").append(Integer.toHexString(element)).append(' '); //$NON-NLS-1$
        }
        buf.append(']');
        return buf.toString();
    }
}
