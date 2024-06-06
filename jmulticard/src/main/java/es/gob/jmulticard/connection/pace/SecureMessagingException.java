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

/** Error en un mensaje seguro de canal inal&aacute;mbrico.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Tobias Senger (tobias@t-senger.de). */
public final class SecureMessagingException extends Exception {

	private static final long serialVersionUID = 8777014446414362735L;

	SecureMessagingException(final Throwable cause) {
		super(cause);
	}

	SecureMessagingException(final String message) {
		super(message);
	}

	SecureMessagingException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
