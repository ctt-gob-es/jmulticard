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
package es.gob.jmulticard.de.tsenger.androsmex.crypto;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
@SuppressWarnings("serial")
public class AmCryptoException extends Exception {

	/**
	 *
	 */
	public AmCryptoException() {
	}

	/**
	 * @param message Descripci&oacute;n del problema.
	 */
	public AmCryptoException(final String message) {
		super(message);
	}

	/**
	 * @param cause Causa del lanzamiento de la excepci&oacute;n.
	 */
	public AmCryptoException(final Throwable cause) {
		super(cause);
	}

	/**
	 * @param message Descripci&oacute;n del problema.
	 * @param cause Causa del lanzamiento de la excepci&oacute;n.
	 */
	public AmCryptoException(final String message, final Throwable cause) {
		super(message, cause);
	}

}
