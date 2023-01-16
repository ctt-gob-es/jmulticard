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
package es.gob.jmulticard.connection;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.asn1.bertlv.BerTlv;
import es.gob.jmulticard.connection.cwa14890.InvalidCryptographicChecksumException;
import es.gob.jmulticard.connection.cwa14890.SecureChannelException;

/** Cifrador de APDU seg&uacute;n CWA-14890 mediante 3DES y MAC de 4 octetos.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Carlos Gamuci Mill&aacute;n. */
public class ApduEncrypterDes extends AbstractApduEncrypter {

	/** Constructor de la clase para operaciones de cifrado cifrado DES. */
	public ApduEncrypterDes() {
        paddingLength = 8;
    }

    /** <i>Tag</i> del TLV de estado de respuesta de una APDU de respuesta. */
    private static final byte TAG_SW_TLV = (byte) 0x99;

    /** <i>Tag</i> del TLV de c&oacute;digo de autenticaci&oacute;n de mensaje (MAC)
     * de una APDU de respuesta. */
    private static final byte TAG_MAC_TLV = (byte) 0x8E;

    /** Longitud de la MAC de las APDU cifradas. */
    private static final byte MAC_LENGTH_4 = 4;

    /** Devuelve la longitud de la MAC de las APDU cifradas.
     * @return Longitud de la MAC de las APDU cifradas. */
    @SuppressWarnings("static-method")
	protected int getMacLength() {
    	return MAC_LENGTH_4;
    }

    @Override
	protected byte[] encryptData(final byte[] data,
			                     final byte[] key,
			                     final byte[] ssc,
			                     final CryptoHelper cryptoHelper) throws IOException {
    	return cryptoHelper.desedeEncrypt(data, key);
    }

    /** Aplica el algoritmo para la generaci&oacute;n de la MAC del mensaje.
     * @param dataPadded Datos sobre los que generar la MAC.
     * @param ssc Contador de secuencia de la operaci&oacute;n.
     * @param kMac Clave Triple DES necesaria para la operaci&oacute;n.
     * @param cryptoHelper Manejador para la realizaci&oacute;n de las operaciones criptogr&aacute;ficas.
     * @return Clave de autenticaci&oacute;n de los datos.
     * @throws IOException Si hay errores de entrada / salida. */
    @Override
	protected byte[] generateMac(final byte[] dataPadded,
                                 final byte[] ssc,
                                 final byte[] kMac,
                                 final CryptoHelper cryptoHelper) throws IOException {

        final byte keyDesBytes[] = new byte[8];
        System.arraycopy(kMac, 0, keyDesBytes, 0, 8);

        byte tmpData[] = cryptoHelper.desEncrypt(ssc, keyDesBytes);

        int i = 0;
        while (i < dataPadded.length - 8) {
            tmpData = cryptoHelper.desEncrypt(
        		HexUtils.xor(tmpData, HexUtils.subArray(dataPadded, i, 8)),
        		keyDesBytes
    		);
            i += 8;
        }

        final byte[] keyTdesBytes = new byte[24];
        System.arraycopy(kMac, 0, keyTdesBytes, 0, 16);
        System.arraycopy(kMac, 0, keyTdesBytes, 16, 8);

        return HexUtils.subArray(
    		cryptoHelper.desedeEncrypt(
				HexUtils.xor(
					tmpData,
					HexUtils.subArray(dataPadded, i, 8)
				),
				keyTdesBytes
			),
			0,
			getMacLength()
		);

    }

    /** Desencripta los datos de una APDU de respuesta protegida.
     * @param responseApdu APDU de respuesta cifrada.
     * @param keyCipher Clave para el descifrado de la respuesta.
     * @param ssc C&oacute;digo de secuencia correspondiente a la respuesta.
     * @param kMac Clave para la verificaci&oacute;n de la respuesta.
     * @param cryptoHelper Manejador para el desencriptado.
     * @return APDU con la respuesta descifrada.
     * @throws IOException Cuando ocurre un error durante la desencriptaci&oacute;n de los datos. */
    @Override
	public ResponseApdu decryptResponseApdu(final ResponseApdu responseApdu,
            								final byte[] keyCipher,
            								final byte[] ssc,
            								final byte[] kMac,
            								final CryptoHelper cryptoHelper) throws IOException {

        // Si el resultado es incorrecto, lo devolvemos para su evaluacion
        if (!responseApdu.isOk()) {
            return new ResponseApdu(
        		responseApdu.getStatusWord().getBytes(),
        		responseApdu.getBytes()
    		);
        }

        // Desciframos y validamos el resultado
        final ByteArrayInputStream recordOfTlvs = new ByteArrayInputStream(responseApdu.getData());
        BerTlv dataTlv = null;
        BerTlv swTlv = null;
        BerTlv macTlv = null;
        try {
            BerTlv tlv = BerTlv.createInstance(recordOfTlvs);
            if (tlv.getTag() == TAG_DATA_TLV) {
                dataTlv = tlv;
                tlv = BerTlv.createInstance(recordOfTlvs);
            }
            if (tlv.getTag() == TAG_SW_TLV) {
            	swTlv = tlv;
                tlv = BerTlv.createInstance(recordOfTlvs);
            }
            if (tlv.getTag() == TAG_MAC_TLV) {
                macTlv = tlv;
            }
        }
        catch (final NegativeArraySizeException e) {
            throw new ApduConnectionException(
        		"Error en el formato de la respuesta remitida por el canal seguro", e //$NON-NLS-1$
    		);
        }

        if (macTlv == null) {
        	throw new SecureChannelException(
    			"No se ha encontrado el TLV del MAC en la APDU" //$NON-NLS-1$
			);
        }
        if (swTlv == null) {
        	throw new SecureChannelException(
    			"No se ha encontrado el TLV del StatusWord en la APDU cifrada" //$NON-NLS-1$
			);
        }

        // Pasamos el TLV completo de datos y el del StatusWord concatenados
        final int tlvsLenght = (dataTlv != null ? 1 + 1 + dataTlv.getValue().length / 128 + dataTlv.getValue().length : 0) + // Tag (1 byte) + Lenght (1 byte + 1 por cada 128) + Value (Value.lenght bytes
        		1 + 1 + swTlv.getValue().length; // Tag (1 byte) + Lenght (1 byte) + Value (Value.lenght bytes)
        verifyMac(
    		HexUtils.subArray(
				responseApdu.getData(),
				0,
				tlvsLenght
			),
			macTlv.getValue(),
			ssc,
			kMac,
			cryptoHelper
		);

        if (dataTlv == null) {
            return new ResponseApdu(swTlv.getValue());
        }

        // Desencriptamos y eliminamos el padding de los datos, teniendo en cuenta que el primer byte
        // de los datos es fijo (0x01) y no cuenta dentro de los datos
        final byte[] decryptedData = removePadding7816(
    		cryptoHelper.desedeDecrypt(
				HexUtils.subArray(dataTlv.getValue(), 1, dataTlv.getValue().length - 1),
				keyCipher
			)
		);

        final byte[] responseApduBytes = new byte[decryptedData.length + swTlv.getValue().length];
        System.arraycopy(decryptedData, 0, responseApduBytes, 0, decryptedData.length);
        System.arraycopy(swTlv.getValue(), 0, responseApduBytes, decryptedData.length, swTlv.getValue().length);

        return new ResponseApdu(
    		responseApduBytes,
    		responseApdu.getBytes()
		);
    }

    /** Comprueba que un c&oacute;digo de verificaci&oacute;n sea correcto con respecto a
     * unos datos y el c&oacute;digo de respuesta de una petici&oacute;n.
     * @param verificableData Datos.
     * @param macTlvBytes C&oacute;digo de verificaci&oacute;n.
     * @param ssc C&oacute;digo de secuencia.
     * @param kMac Clave para la generaci&oacute;n del MAC.
     * @param cryptoHelper Manejador de operaciones criptogr&aacute;ficas. */
    private void verifyMac(final byte[] verificableData,
    		               final byte[] macTlvBytes,
    		               final byte[] ssc,
    		               final byte[] kMac,
    		               final CryptoHelper cryptoHelper) {

    	final byte[] calculatedMac;
    	try {
    		calculatedMac = generateMac(addPadding7816(verificableData, paddingLength), ssc, kMac, cryptoHelper);
    	}
    	catch (final IOException e) {
    		throw new SecurityException(
				"No se pudo calcular el MAC teorico de la respuesta de la tarjeta para su verificacion", e //$NON-NLS-1$
			);
		}

    	// Comparamos que el MAC recibido sea igual que el MAC que debimos recibir
        if (!HexUtils.arrayEquals(macTlvBytes, calculatedMac)) {
            throw new InvalidCryptographicChecksumException();
        }
	}
}