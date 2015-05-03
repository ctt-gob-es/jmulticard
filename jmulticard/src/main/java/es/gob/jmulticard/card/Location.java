/*
 * Controlador Java de la Secretaria de Estado de Administraciones Publicas
 * para el DNI electronico.
 *
 * El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
 * que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
 * para la realizacion de procesos de autenticacion, firma electronica y validacion
 * de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
 * el acceso a los certificados y claves del DNI electronico, asi como la realizacion
 * de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
 * sido disenado para su funcionamiento independiente del sistema operativo final.
 *
 * Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
 * e Impulso de la Administracion Electronica
 *
 * Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
 * o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
 * licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
 * en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
 * su compatibilidad con otros componentes.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * Lesser GNU General Public License publicada por la Free Software Foundation,
 * tanto en la version 2.1 de la Licencia, o en una version posterior.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * European Union Public License publicada por la Comision Europea,
 * tanto en la version 1.1 de la Licencia, o en una version posterior.
 *
 * Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
 *
 * Deberia recibir una copia de la European Union Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
 *
 * Este programa es distribuido con la esperanza de que sea util, pero
 * SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
 * o idoneidad para un proposito particular.
 */
package es.gob.jmulticard.card;

import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import es.gob.jmulticard.HexUtils;

/** Ruta hacia un fichero (EF o DF) ISO 7816-4.
 * Un fichero (EF) o directorio (DF) se identifica por un par de bytes o palabra
 * que representan su identificador &uacute;nico. Todos los ficheros tienen como
 * antepasado al fichero MF, que corresponde con el identificador 0x3F00.
 * @author Alberto Mart&iacute;nez */
public final class Location {

    private static final int MASTER_FILE_ID = 0x3F00;

    private Vector<Integer> path = new Vector<Integer>();

    private static final Map<String, Integer> HEXBYTES = new HashMap<String, Integer>();

    static {
        final String hex[] = {
    		"a", "b", "c", "d", "e", "f" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$
        };
        for (int i = 0; i < 9; i++) {
            Location.HEXBYTES.put(String.valueOf(i), Integer.valueOf(String.valueOf(i)));
        }
        for (int i = 10; i < 16; i++) {
            Location.HEXBYTES.put(hex[i - 10], Integer.valueOf(String.valueOf(i)));
            Location.HEXBYTES.put(hex[i - 10].toUpperCase(), Integer.valueOf(String.valueOf(i)));
        }
    }

    /** Constructor de la clase Location.
     * @param absolutePath Ruta absoluta donde se encuentra el fichero */
    public Location(final String absolutePath) {
        init(absolutePath);
    }

    /** Constructor privado. Necesario para algunas operaciones internas.
     * @param path Ruta asociada */
    private Location(final Vector<Integer> path) {
        if (path != null) {
            final int numElements = path.size();
            this.path = new Vector<Integer>(numElements);
            for (int i = 0; i < numElements; i++) {
                this.path.insertElementAt(path.elementAt(i), i);
            }
        }
    }

    /** Obtiene el fichero hijo del <code>Location</code> proporcionado.
     * @return Devuelve un objeto location que contiene el hijo del fichero actual si existe. Si no tiene hijos devuelve null. */
    public Location getChild() {
        final Location aux = new Location(this.path);
        if (aux.path != null && aux.path.size() > 1) {
            aux.path.removeElementAt(0);
            return aux;
        }
        return null;
    }

    /** Obtiene la direcci&oacute;n f&iacute;sica del fichero actualmente apuntado.
     * @return Una palabra con la direcci&oacute;n de memoria seleccionada. */
    public byte[] getFile() {
        final int address = this.path.elementAt(0).intValue();
        return new byte[] {
                (byte) (address >> 8 & 0xFF), (byte) (address & 0xFF)
        };
    }

    /** Obtiene la direcci&oacute;n del &uacute;ltimo fichero de la ruta indicada.
     * @return Path con la direcci&oacute;n del fichero. */
    public byte[] getLastFilePath() {
    	if (this.path.size() < 1) {
    		return null;
    	}
        final int address = this.path.elementAt(this.path.size() - 1).intValue();
        return new byte[] {
                (byte) (address >> 8 & 0xFF), (byte) (address & 0xFF)
        };
    }

    /** Comprueba que la ruta indicada corresponda al patr&oacute;n alfanum&eacute;rico.
     * @param absolutePath Ruta a comprobar
     * @throws IllegalArgumentException si la ruta es inv&aacute;lida */
    private static void checkValidPath(final String absolutePath) throws IllegalArgumentException {
    	if (absolutePath == null) {
    		throw new IllegalArgumentException("Ruta nula"); //$NON-NLS-1$
    	}
        if (absolutePath.length() == 0) {
            throw new IllegalArgumentException("Ruta vacia"); //$NON-NLS-1$
        }
        if (absolutePath.trim().length() % 4 != 0) {
        	throw new IllegalArgumentException(
    			"Un location valido debe estar compuesto por grupos pares de octetos: " + absolutePath //$NON-NLS-1$
			);
        }
        final String aux = absolutePath.toLowerCase();
        for (int i = 0; i < absolutePath.length(); i++) {
        	final char currentChar = aux.charAt(i);
            if (!(currentChar >= '0' && currentChar <= '9' || currentChar >= 'a' && currentChar <= 'f')) {
            	throw new IllegalArgumentException(
        			"Encontrado el caracter invalido '" + currentChar + "'en la ruta '" + absolutePath + "'" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    			);
            }
        }
    }

    /** Genera un vector de enteros con los diversos identificadores de DF y EF
     * indicados en la ruta absoluta que se proporciona como par&aacute;metro.
     * @param absolutePath Ruta absoluta */
    private void init(final String absolutePath) {

        checkValidPath(absolutePath);

        for (int i = 0; i < absolutePath.length(); i = i + 4) {
            final int mm = Location.HEXBYTES.get(absolutePath.substring(i, i + 1)).intValue();
            final int ml = Location.HEXBYTES.get(absolutePath.substring(i + 1, i + 2)).intValue();
            final int lm = Location.HEXBYTES.get(absolutePath.substring(i + 2, i + 3)).intValue();
            final int ll = Location.HEXBYTES.get(absolutePath.substring(i + 3, i + 4)).intValue();
            int id = ll;
            id += lm << 4;
            id += ml << 8;
            id += mm << 4 << 8;

            if (id != Location.MASTER_FILE_ID) {
                this.path.addElement(Integer.valueOf(String.valueOf(id)));
            }
        }
    }

    /** Devuelve una representaci&oacute;n de la ruta absoluta del fichero separando cada identificador mediante barras.
     * @see java.lang.Object#toString() */
    @Override
    public String toString() {
        final StringBuffer buffer = new StringBuffer();
        if (this.path != null && !this.path.isEmpty()) {
            buffer.append("3F00"); //$NON-NLS-1$
            for (int i = 0; i < this.path.size(); i++) {
                final Integer integer = this.path.elementAt(i);
                buffer.append('/').append(HexUtils.hexify(new byte[] {
                        (byte) (integer.shortValue() >> 8), integer.byteValue()
                }, false));
            }
        }
        return buffer.toString();
    }
}