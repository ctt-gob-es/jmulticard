	package es.gob.jmulticard.card.fnmt.ceres;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.ceres.CeresVerifyApduCommand;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.fnmt.ceres.asn1.CeresCdf;
import es.gob.jmulticard.card.fnmt.ceres.asn1.CeresPrKdf;
import es.gob.jmulticard.card.iso7816eight.Iso7816EightCard;
import es.gob.jmulticard.card.iso7816four.FileNotFoundException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** Tarjeta FNMT-RCM CERES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class Ceres extends Iso7816EightCard implements CryptoCard {

	private static final byte CLA = (byte) 0x00;

    private static final Location CDF_LOCATION = new Location("50156004"); //$NON-NLS-1$
    private static final Location PRKDF_LOCATION = new Location("50156001"); //$NON-NLS-1$

    /** Nombre del Fichero Maestro. */
    private static final String MASTER_FILE_NAME = "Master.File"; //$NON-NLS-1$

    /** Octeto que identifica una verificaci&oacute;n fallida del PIN */
    private final static byte ERROR_PIN_SW1 = (byte) 0x63;

    private Map<String, X509Certificate> certs;
    private Map<String, Location> keys;

	/** Construye una clase que representa una tarjeta FNMT-RCM CERES.
	 * @param conn Conexi&oacute;n con la tarjeta.
	 * @throws ApduConnectionException Si hay problemas con la conexi&oacute;n proporcionada.
	 * @throws InvalidCardException Si la tarjeta conectada no es una FNMT-RCM CERES.
	 */
	public Ceres(final ApduConnection conn) throws ApduConnectionException, InvalidCardException {
		super(CLA, conn);
		getConnection().open();
		try {
			preload();
		}
		catch (final Exception e) {
			throw new ApduConnectionException("Error cargando las estructuras iniciales de la tarjeta: " + e, e); //$NON-NLS-1$
		}
	}

	private void preload() throws ApduConnectionException,
	                              Iso7816FourCardException,
	                              IOException,
	                              CertificateException,
	                              Asn1Exception,
	                              TlvException {
		// Cargamos el CDF
        final CeresCdf cdf = new CeresCdf();
        cdf.setDerValue(selectFileByLocationAndRead(CDF_LOCATION));

        // Leemos los certificados segun las rutas del CDF
        final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
        this.certs = new LinkedHashMap<String, X509Certificate>(cdf.getCertificateCount());
        for (int i=0; i<cdf.getCertificateCount(); i++) {
        	final Location l = new Location(cdf.getCertificatePath(i).replace("\\", "").trim()); //$NON-NLS-1$ //$NON-NLS-2$
        	final X509Certificate cert = (X509Certificate) cf.generateCertificate(
    			new ByteArrayInputStream(
					deflate(
						selectFileByLocationAndRead(l)
					)
				)
			);
        	this.certs.put(i + " " + cert.getSerialNumber(), cert); //$NON-NLS-1$
        }

        System.out.println(cdf.toString());

        final CeresPrKdf prkdf = new CeresPrKdf();
        prkdf.setDerValue(selectFileByLocationAndRead(PRKDF_LOCATION));

        System.out.println(prkdf.toString());

        if (prkdf.getKeyCount() != this.certs.size()) {
        	throw new IllegalStateException(
    			"El numero de claves de la tarjeta (" + prkdf.getKeyCount() + ") no coincide con el de certificados (" + this.certs.size() + ")" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			);
        }
        this.keys = new LinkedHashMap<String, Location>(this.certs.size());
        final String[] aliases = getAliases();
        for (int i=0; i<this.certs.size(); i++) {
        	this.keys.put(aliases[i], new Location(prkdf.getKeyPath(i).replace("\\", "").trim())); //$NON-NLS-1$ //$NON-NLS-2$
        }
	}

	@Override
	public String[] getAliases() throws CryptoCardException {
		return this.certs.keySet().toArray(new String[0]);
	}

	@Override
	public X509Certificate getCertificate(final String alias) throws CryptoCardException, BadPinException {
		return this.certs.get(alias);
	}

	@Override
	public PrivateKeyReference getPrivateKey(final String alias) throws CryptoCardException {
		return new CeresPrivateKeyReference(this.keys.get(alias));
	}

	@Override
	public byte[] sign(final byte[] data, final String algorithm, final PrivateKeyReference keyRef) throws CryptoCardException, BadPinException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void selectMasterFile() throws ApduConnectionException, FileNotFoundException, Iso7816FourCardException {
		selectFileByName(MASTER_FILE_NAME);
	}

	@Override
	public void verifyPin(final PasswordCallback pinPc) throws ApduConnectionException, BadPinException {
		final CommandApdu chv = new CeresVerifyApduCommand(CLA, pinPc);
		final ResponseApdu verifyResponse = sendArbitraryApdu(chv);
        if (!verifyResponse.isOk()) {
            if (verifyResponse.getStatusWord().getMsb() == ERROR_PIN_SW1) {
            	throw new BadPinException(verifyResponse.getStatusWord().getLsb() - (byte) 0xC0);
            }
        }
	}

	@Override
	public String getCardName() {
		return "FNMT-RCM CERES"; //$NON-NLS-1$
	}

    /** Descomprime un certificado contenido en la tarjeta CERES.
     * @param compressedCertificate Certificado comprimido en ZIP a partir del 9 byte.
     * @return Certificado codificado.
     * @throws IOException Cuando se produce un error en la descompresion del certificado. */
    private static byte[] deflate(final byte[] compressedCertificate) throws IOException {
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        final Inflater decompressor = new Inflater();
        decompressor.setInput(compressedCertificate, 8, compressedCertificate.length - 8);
        final byte[] buf = new byte[1024];
        try {
            // Descomprimimos los datos
            while (!decompressor.finished()) {
                final int count = decompressor.inflate(buf);
                if (count == 0) {
                    throw new DataFormatException();
                }
                buffer.write(buf, 0, count);
            }
            // Obtenemos los datos descomprimidos
            return buffer.toByteArray();
        }
        catch (final DataFormatException ex) {
            throw new IOException("Error al descomprimir el certificado: " + ex, ex); //$NON-NLS-1$
        }
    }

}
