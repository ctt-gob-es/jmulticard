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

/** Error en operaci&oacute;n criptogr&aacute;fica del canal inal&aacute;mbrico.
 * @author Tobias Senger (tobias@t-senger.de). */
public final class AmCryptoException extends Exception {

	private static final long serialVersionUID = -1916093589582119573L;

	AmCryptoException(final Throwable cause) {
		super(cause);
	}

	AmCryptoException(final String desc, final Throwable e) {
		super(desc, e);
	}

}
