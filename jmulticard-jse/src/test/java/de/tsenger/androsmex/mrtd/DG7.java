/*
 * Decompiled with CFR 0_110.
 */
package de.tsenger.androsmex.mrtd;

public class DG7 {
    private static final byte HEADER_PORTRAIT_TAG = 101;
    private static final short DISPLAYED_PORTRAIT = 24384;
    private static final byte HEADER_SIGNATURE_TAG = 103;
    private static final short DISPLAYED_SIGNATURE = 24387;
    private byte[] imageBytes;
    private byte[] rawData;

    public DG7(byte[] rawBytes) {
        this.rawData = rawBytes.clone();
        byte[] signatureDataBlock = ASN1Tools.extractTLV((byte)24387, this.rawData, 0);
        byte[] imageData = new byte[signatureDataBlock.length - 5];
        System.arraycopy(signatureDataBlock, 5, imageData, 0, imageData.length);
        this.imageBytes = imageData.clone();
    }

    public byte[] getBytes() {
        return this.rawData;
    }

    public byte[] getImageBytes() {
        return this.imageBytes;
    }
}

