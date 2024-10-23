/*
 * Copyright 2008 ZXing authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package es.gob.jmulticard.card.icao.vdsned;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/** Decodificador de texto en formato C40.
 * @author ZXing authors
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class C40Decoder {

	/** Juego b&aacute;sico de caracteres C40 (con el espacio cambiado a '&lt;'). */
	private static final char[] C40_BASIC_SET_CHARS = {
		'*', '*', '*', '<', '0', '1', '2', '3', '4', '5',
		'6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
		'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
	};

	/** Juego extendido de caracteres C40. */
	private static final char[] C40_SHIFT2_SET_CHARS = {
		'!', '"', '#', '$', '%', '&', '\'', '(', ')', '*',
		'+', ',', '-', '.', '/', ':', ';', '<', '=', '>',
		'?', '@', '[', '\\', ']', '^', '_'
	};

	private C40Decoder() {
		// No instanciable
	}

	/** Decodifica un texto en formato C40 seg&uacute;n la ISO 16022:2006
	 * (secci&oacute;n 5&#46;2&#46;5. anexo C, y tabla C&#46;1.
	 * @param c40encoded Texto codificado como C40.
	 * @return Texto decodificado.
	 * @throws IOException Si no se puede decodificar el texto o este no estaba en
	 *                     formato C40. */
	static String decode(final byte[] c40encoded) throws IOException {

		// Tres caracteres C40 se codifican en un valor de 16 bits como:
		// (1600 * C1) + (40 * C2) + C3 + 1

		final StringBuilder result = new StringBuilder();
		final ByteArrayInputStream bits = new ByteArrayInputStream(c40encoded);

		boolean upperShift = false;

		do {
			// Si solo queda un byte, entonces se codifica en ASCII
			if (bits.available() == 1) {
				break;
			}
			final int firstByte = bits.read();
			if (firstByte == 254) { // Unlatch codeword
				break;
			}

			final int[] cValues = parseTwoBytes(firstByte, bits.read());

			int shift = 0;
			for (int i = 0; i < 3; i++) {
				final int cValue = cValues[i];
				switch (shift) {
					case 0:
						if (cValue < 3) {
							shift = cValue + 1;
						}
						else if (upperShift) {
							result.append((char) (C40_BASIC_SET_CHARS[cValue] + 128));
							upperShift = false;
						}
						else {
							result.append(C40_BASIC_SET_CHARS[cValue]);
						}
						break;
					case 1:
						if (upperShift) {
							result.append((char) (cValue + 128));
							upperShift = false;
						}
						else {
							result.append(cValue);
						}
						shift = 0;
						break;
					case 2:
						if (cValue < 27) {
							if (upperShift) {
								result.append((char) (C40_SHIFT2_SET_CHARS[cValue] + 128));
								upperShift = false;
							}
							else {
								result.append(C40_SHIFT2_SET_CHARS[cValue]);
							}
						}
						else if (cValue == 27 || cValue != 30) { // FNC1
							throw new IOException();
						}
						else { // Upper Shift
							upperShift = true;
						}
						shift = 0;
						break;
					case 3:
						if (upperShift) {
							result.append((char) (cValue + 224));
							upperShift = false;
						}
						else {
							result.append((char) (cValue + 96));
						}
						shift = 0;
						break;
					default:
						throw new IOException();
					}
			}
		} while (bits.available() > 0);

		return result.toString();
	}

	private static int[] parseTwoBytes(final int firstByte, final int secondByte) {
		int fullBitValue = (firstByte << 8) + secondByte - 1;
		final int[] result = new int[3];
		int temp = fullBitValue / 1600;
		result[0] = temp;
		fullBitValue -= temp * 1600;
		temp = fullBitValue / 40;
		result[1] = temp;
		result[2] = fullBitValue - temp * 40;
		return result;
	}
}
