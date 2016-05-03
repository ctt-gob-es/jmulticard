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

/**
 * Excepci&oacute; que lanza la clase SecureMessaging.
 *
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
@SuppressWarnings("serial")
public class SecureMessagingException extends Exception {

	SecureMessagingException() {
	}

	SecureMessagingException(String message, Throwable cause) {
		super(message, cause);
	}

	SecureMessagingException(Throwable cause) {
		super(cause);
	}

	SecureMessagingException(String message) {
		super(message);
	}
}
