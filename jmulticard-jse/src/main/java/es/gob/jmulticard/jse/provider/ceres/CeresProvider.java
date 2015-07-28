package es.gob.jmulticard.jse.provider.ceres;

import java.security.Provider;
import java.security.ProviderException;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.fnmt.ceres.Ceres;

/** Proveedor criptogr&aacute;fico JCA para tarjeta FNMT-RCM.CERES.
 * Crea dos servicios:
 * <dl>
 * <dt><code>KeyStore</code></dt>
 * <dd><i>CERES</i></dd>
 * <dt><code>Signature</code></dt>
 * <dd><i>SHA1withRSA</i>, <i>SHA256withRSA</i>, <i>SHA384withRSA</i>, <i>SHA512withRSA</i></dd>
 * </dl>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class CeresProvider extends Provider {

    private static final String SHA512WITH_RSA = "SHA512withRSA"; //$NON-NLS-1$

    private static final String SHA384WITH_RSA = "SHA384withRSA"; //$NON-NLS-1$

    private static final String SHA256WITH_RSA = "SHA256withRSA"; //$NON-NLS-1$

    private static final String SHA1WITH_RSA = "SHA1withRSA"; //$NON-NLS-1$

    private static final String ES_GOB_JMULTICARD_CARD_CERES_PRIVATE_KEY = "es.gob.jmulticard.jse.provider.ceres.CeresPrivateKey"; //$NON-NLS-1$

    private static final long serialVersionUID = -1046745919235177156L;

    private static final String INFO = "Proveedor para tarjeta FNMT-RCM-CERES"; //$NON-NLS-1$
    private static final double VERSION = 0.1d;
    private static final String NAME = "CeresJCAProvider"; //$NON-NLS-1$

    private static ApduConnection defaultConnection = null;

    /** Obtiene de forma est&aacute;tica el tipo de conexi&oacute;n de APDU que debe usar el <i>keyStore</i>.
     * Si es nula (se ha invocado al constructor por defecto), es el propio <code>KeyStore</code> el que decide que
     * conexi&oacute;n usar.
     * @return Conexi&oacute;n por defecto */
    static ApduConnection getDefaultApduConnection() {
    	return defaultConnection;
    }

    /** Crea un proveedor JCA para tarjeta FNMT-RCM-CERES con la conexi&oacute;n por defecto. */
    public CeresProvider() {
    	this(null);
    }

    /** Crea un proveedor JCA para tarjeta FNMT-RCM-CERES.
     * @param conn Conexi&oacute;n a usar para el env&iacute;o y recepci&oacute;n de APDU. */
    public CeresProvider(final ApduConnection conn) {
        super(NAME, VERSION, INFO);

        try {
			defaultConnection = conn == null ?
				(ApduConnection) Class.forName("es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection").newInstance() : //$NON-NLS-1$
					conn;
		}
        catch (final Exception e) {
			throw new ProviderException(
				"No se ha proporcionado una conexion con un lector y no ha podido instanciarse la por defecto: " + e, e //$NON-NLS-1$
			);
		}

        try {
			Ceres.connect(defaultConnection);
			defaultConnection.close();
		}
        catch (final Exception e) {
        	throw new ProviderException(
				"No se ha podido conectar con la tarjeta CERES: " + e, e //$NON-NLS-1$
			);
		}

        // KeyStore
        put("KeyStore.CERES", "es.gob.jmulticard.jse.provider.ceres.CeresKeyStoreImpl"); //$NON-NLS-1$ //$NON-NLS-2$

        // Motores de firma
        put("Signature.SHA1withRSA",   "es.gob.jmulticard.jse.provider.ceres.CeresSignatureImpl$Sha1"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA256withRSA", "es.gob.jmulticard.jse.provider.ceres.CeresSignatureImpl$Sha256"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA384withRSA", "es.gob.jmulticard.jse.provider.ceres.CeresSignatureImpl$Sha384"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA512withRSA", "es.gob.jmulticard.jse.provider.ceres.CeresSignatureImpl$Sha512"); //$NON-NLS-1$ //$NON-NLS-2$

        // Claves soportadas
        put("Signature.SHA1withRSA SupportedKeyClasses",   CeresProvider.ES_GOB_JMULTICARD_CARD_CERES_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA256withRSA SupportedKeyClasses", CeresProvider.ES_GOB_JMULTICARD_CARD_CERES_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA384withRSA SupportedKeyClasses", CeresProvider.ES_GOB_JMULTICARD_CARD_CERES_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA512withRSA SupportedKeyClasses", CeresProvider.ES_GOB_JMULTICARD_CARD_CERES_PRIVATE_KEY); //$NON-NLS-1$

        // Alias de los nombres de algoritmos de firma
        put("Alg.Alias.Signature.1.2.840.113549.1.1.5",     CeresProvider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", CeresProvider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.1.3.14.3.2.29",            CeresProvider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHAwithRSA",               CeresProvider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-1withRSA",             CeresProvider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA1withRSAEncryption",    CeresProvider.SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-1withRSAEncryption",   CeresProvider.SHA1WITH_RSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.113549.1.1.11",     CeresProvider.SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.11", CeresProvider.SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-256withRSA",            CeresProvider.SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-256withRSAEncryption",  CeresProvider.SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA256withRSAEncryption",   CeresProvider.SHA256WITH_RSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.113549.1.1.12",     CeresProvider.SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.12", CeresProvider.SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-384withRSA",            CeresProvider.SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-384withRSAEncryption",  CeresProvider.SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA384withRSAEncryption",   CeresProvider.SHA384WITH_RSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.113549.1.1.13",     CeresProvider.SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.13", CeresProvider.SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-512withRSA",            CeresProvider.SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-512withRSAEncryption",  CeresProvider.SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA512withRSAEncryption",   CeresProvider.SHA512WITH_RSA); //$NON-NLS-1$
    }

}