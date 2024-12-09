package org.bouncycastle.asn1.x509;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * Generator for X.509 extensions
 */
public class ExtensionsGenerator
{
    private Hashtable extensions = new Hashtable();
    private Vector extOrdering = new Vector();
    private static final Set dupsAllowed;


    static
    {
        final Set dups = new HashSet();
        dups.add(Extension.subjectAlternativeName);
        dups.add(Extension.issuerAlternativeName);
        dups.add(Extension.subjectDirectoryAttributes);
        dups.add(Extension.certificateIssuer);
        dupsAllowed = Collections.unmodifiableSet(dups);
    }

    /**
     * Reset the generator
     */
    public void reset()
    {
        this.extensions = new Hashtable();
        this.extOrdering = new Vector();
    }

    /**
     * Add an extension with the given oid and the passed in value to be included
     * in the OCTET STRING associated with the extension.
     *
     * @param oid      OID for the extension.
     * @param critical true if critical, false otherwise.
     * @param value    the ASN.1 object to be included in the extension.
     * @throws IOException If IO error occurs.
     */
    public void addExtension(
        final ASN1ObjectIdentifier oid,
        final boolean critical,
        final ASN1Encodable value)
        throws IOException
    {
        this.addExtension(oid, critical, value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    /**
     * Add an extension with the given oid and the passed in byte array to be wrapped in the
     * OCTET STRING associated with the extension.
     *
     * @param oid      OID for the extension.
     * @param critical true if critical, false otherwise.
     * @param value    the byte array to be wrapped.
     */
    public void addExtension(
        final ASN1ObjectIdentifier oid,
        final boolean critical,
        final byte[] value)
    {
        if (this.extensions.containsKey(oid))
        {
            if (dupsAllowed.contains(oid))
            {
                final Extension existingExtension = (Extension)this.extensions.get(oid);
                final ASN1Sequence seq1 = ASN1Sequence.getInstance(ASN1OctetString.getInstance(existingExtension.getExtnValue()).getOctets());
                final ASN1Sequence seq2 = ASN1Sequence.getInstance(value);

                final ASN1EncodableVector items = new ASN1EncodableVector(seq1.size() + seq2.size());
                for (final Enumeration en = seq1.getObjects(); en.hasMoreElements();)
                {
                    items.add((ASN1Encodable)en.nextElement());
                }
                for (final Enumeration en = seq2.getObjects(); en.hasMoreElements();)
                {
                    items.add((ASN1Encodable)en.nextElement());
                }

                try
                {
                    this.extensions.put(oid, new Extension(oid, critical, new DERSequence(items).getEncoded()));
                }
                catch (final IOException e)
                {
                    throw new ASN1ParsingException(e.getMessage(), e);
                }
            }
            else
            {
                throw new IllegalArgumentException("extension " + oid + " already added");
            }
        }
        else
        {
            this.extOrdering.addElement(oid);
            this.extensions.put(oid, new Extension(oid, critical, new DEROctetString(Arrays.clone(value))));
        }
    }

    /**
     * Add a given extension.
     *
     * @param extension the full extension value.
     */
    public void addExtension(
        final Extension extension)
    {
        if (this.extensions.containsKey(extension.getExtnId()))
        {
            throw new IllegalArgumentException("extension " + extension.getExtnId() + " already added");
        }

        this.extOrdering.addElement(extension.getExtnId());
        this.extensions.put(extension.getExtnId(), extension);
    }

    /**
     * Replace an extension with the given oid and the passed in value to be included
     * in the OCTET STRING associated with the extension.
     *
     * @param oid      OID for the extension.
     * @param critical true if critical, false otherwise.
     * @param value    the ASN.1 object to be included in the extension.
     * @throws IOException If IO error occurs.
     */
    public void replaceExtension(
        final ASN1ObjectIdentifier oid,
        final boolean critical,
        final ASN1Encodable value)
        throws IOException
    {
        this.replaceExtension(oid, critical, value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    /**
     * Replace an extension with the given oid and the passed in byte array to be wrapped in the
     * OCTET STRING associated with the extension.
     *
     * @param oid      OID for the extension.
     * @param critical true if critical, false otherwise.
     * @param value    the byte array to be wrapped.
     */
    public void replaceExtension(
        final ASN1ObjectIdentifier oid,
        final boolean critical,
        final byte[] value)
    {
        this.replaceExtension(new Extension(oid, critical, value));
    }

    /**
     * Replace a given extension.
     *
     * @param extension the full extension value.
     */
    public void replaceExtension(
        final Extension extension)
    {
        if (!this.extensions.containsKey(extension.getExtnId()))
        {
            throw new IllegalArgumentException("extension " + extension.getExtnId() + " not present");
        }

        this.extensions.put(extension.getExtnId(), extension);
    }

    /**
     * Remove a given extension.
     *
     * @param oid OID for the extension to remove.
     */
    public void removeExtension(
        final ASN1ObjectIdentifier oid)
    {
        if (!this.extensions.containsKey(oid))
        {
            throw new IllegalArgumentException("extension " + oid + " not present");
        }

        this.extOrdering.removeElement(oid);
        this.extensions.remove(oid);
    }

    /**
     * Return if the extension indicated by OID is present.
     *
     * @param oid the OID for the extension of interest.
     * @return the Extension, or null if it is not present.
     */
    public boolean hasExtension(final ASN1ObjectIdentifier oid)
    {
        return this.extensions.containsKey(oid);
    }

    /**
     * Return the current value of the extension for OID.
     *
     * @param oid the OID for the extension we want to fetch.
     * @return true if a matching extension is present, false otherwise.
     */
    public Extension getExtension(final ASN1ObjectIdentifier oid)
    {
        return (Extension)this.extensions.get(oid);
    }

    /**
     * Return true if there are no extension present in this generator.
     *
     * @return true if empty, false otherwise
     */
    public boolean isEmpty()
    {
        return this.extOrdering.isEmpty();
    }

    /**
     * Generate an Extensions object based on the current state of the generator.
     *
     * @return an X09Extensions object.
     */
    public Extensions generate()
    {
        final Extension[] exts = new Extension[this.extOrdering.size()];

        for (int i = 0; i != this.extOrdering.size(); i++)
        {
            exts[i] = (Extension)this.extensions.get(this.extOrdering.elementAt(i));
        }

        return new Extensions(exts);
    }

    public void addExtension(final Extensions extensions)
    {
        final ASN1ObjectIdentifier[] oids = extensions.getExtensionOIDs();
        for (int i = 0; i != oids.length; i++)
        {
            final ASN1ObjectIdentifier ident = oids[i];
            final Extension ext = extensions.getExtension(ident);
            addExtension(ASN1ObjectIdentifier.getInstance(ident), ext.isCritical(), ext.getExtnValue().getOctets());
        }
    }
}
