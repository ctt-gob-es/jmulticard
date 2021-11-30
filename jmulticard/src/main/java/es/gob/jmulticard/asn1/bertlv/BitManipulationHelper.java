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

/** Utilidades para la manipulaci&oacute;n de bits y octetos.
 * @author Isaac Levin */
final class BitManipulationHelper {

	private BitManipulationHelper() {
		// No permitimos la instancacion
	}

	/** Obtiene el valor del bit de la posici&oacute;n indicada.
	 * @param value Valor entero a considerar como binario de entrada.
	 * @param position Posici&oacute;n del bit, empezando desde 1.
	 * @return <code>true</code> si el valor del bit es 1, <code>false</code>
	 *         si es 0. */
	static boolean getBitValue(final int value, final int position) {

		if (position > 32) {
			throw new BerParsingException(
				"No se puede obtener el valor del bit de la posicion " + //$NON-NLS-1$
					position + ", un entero en Java tiene solo 32 bits" //$NON-NLS-1$
			);
		}
		int bitPosition = position;
		bitPosition--; // Lo pasamos a contador desde 0
		final int mask = 1 << bitPosition;
		return (value & mask) != 0;
	}

	/** Establece el valor del bit de la posici&oacute;n indicada.
	 * @param value Valor entero a considerar como binario de entrada.
	 * @param position Posici&oacute;n del bit, empezando desde 1.
	 * @param bitValue Valor a establecer, <code>true</code> para 1, <code>false</code> para 0.
	 * @return Valor entero, considerado como binario, con el bit indicado cambiado. */
	static int setBitValue(final int value, final int position, final boolean bitValue) {
		if (position > 32) {
			throw new BerParsingException(
				"No se puede establecer el valor del bit de la posicion  " //$NON-NLS-1$
					+ position + ", un entero en Java tiene solo 32 bits" //$NON-NLS-1$
			);
		}
		int bitPosition = position;
		bitPosition--; // Lo pasamos a contador desde 0
		final int mask = 1 << bitPosition;
		if (bitValue) {
			// Lo establecemos a 1
			return value | mask;
		}
		// Lo establecemos a 0
		return value & ~mask;
	}

	static byte[] mergeArrays(final byte[] buf1, final byte[] buf2) {
		final byte[] resBuf = new byte[buf1.length + buf2.length];
		System.arraycopy(buf1, 0, resBuf, 0, buf1.length);
		System.arraycopy(buf2, 0, resBuf, buf1.length, buf2.length);
		return resBuf;
	}
}
