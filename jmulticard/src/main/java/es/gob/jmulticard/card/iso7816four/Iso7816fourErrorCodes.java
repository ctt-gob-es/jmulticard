package es.gob.jmulticard.card.iso7816four;

import java.util.Hashtable;

import es.gob.jmulticard.apdu.StatusWord;

/** C&oacute;digos comunes de de error de ISO-7816-4.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Iso7816fourErrorCodes {

	private Iso7816fourErrorCodes() {
		// No instanciable
	}

    private static final Hashtable<StatusWord, String> ERRORS = new Hashtable<>();
    static {
        ERRORS.put(new StatusWord((byte) 0x62, (byte) 0x83), "El fichero seleccionado esta invalidado (6283)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x65, (byte) 0x81), "Fallo en la memoria (6581)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x67, (byte) 0x00), "Longitud incorrecta (6700)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x68, (byte) 0x82), "Securizacion de mensajes no soportada (6882)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x69, (byte) 0x82), "Condiciones de seguridad no satisfechas (6982)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x69, (byte) 0x83), "Metodo de autenticacion bloqueado (6983)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x69, (byte) 0x84), "Dato referenciado invalido (6984)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x69, (byte) 0x85), "Condiciones de uso no satisfechas (6985)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x69, (byte) 0x86), "Comando no permitido [no existe ningun EF seleccionado] (6986)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x69, (byte) 0x87), "Falta un objeto necesario en el mensaje seguro (6987)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x69, (byte) 0x88), "Objetos de datos incorrectos para el mensaje seguro (6988)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x80), "Parametros incorrectos en el campo de datos (6A80)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x81), "Funcion no soportada (6A81)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x82), "No se encuentra el fichero (6A82)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x83), "Registro no encontrado (6A83)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x84), "No hay suficiente espacio de memoria en el fichero (6A84)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x85), "La longitud de datos (Lc) es incompatible con la estructura TLV (6A85)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x86), "Parametros incorrectos en P1 o P2 (6A86)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x87), "La longitud de los datos es inconsistente con P1-P2 (6A87)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x88), "Datos referenciados no encontrados (6A88)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x89), "El fichero ya existe (6A89)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6A, (byte) 0x8A), "El nombre del DF ya existe (6A8A)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6B, (byte) 0x00), "Parametro(s) incorrecto(s) P1-P2 (6B00)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6E, (byte) 0x00), "Clase no soportada (6E00)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6D, (byte) 0x00), "Comando no permitido en la fase de vida actual (6D00)"); //$NON-NLS-1$
        ERRORS.put(new StatusWord((byte) 0x6F, (byte) 0x00), "Diagnostico no preciso (6F00)"); //$NON-NLS-1$
    }

    /** Obtiene la descripci&oacute;n del error asociado a una determinada <i>Status Word</i>.
     * @param sw <i>Status Word</i> de entrada.
     * @return Descripci&oacute;n del error asociado a la <i>Status Word</i> proporcionada. */
    public static String getErrorDescription(final StatusWord sw) {
    	if (sw == null) {
    		return "Status Word nula"; //$NON-NLS-1$
    	}
    	if (ERRORS.containsKey(sw)) {
    		return ERRORS.get(sw);
    	}
    	return sw.toString();
    }

}
