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

/** Excepci&oacute;n en el an&aacute;lisis de un TLV.
 * @author Isaac Levin. */
public final class BerParsingException extends RuntimeException {

	private static final long serialVersionUID = 4729535660890694828L;

    /** Construye una excepci&oacute;n en el an&aacute;lisis de un TLV.
     * @param message Mensaje de la excepci&oacute;n. */
    public BerParsingException(final String message) {
        super(message);
    }

    /** Construye una excepci&oacute;n en el an&aacute;lisis de un TLV.
     * @param cause Causa de la excepci&oacute;n. */
    public BerParsingException(final Throwable cause) {
        super(cause);
    }
}
