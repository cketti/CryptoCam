package com.android.camera.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.Iterator;

import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.bcpg.BCPGOutputStream;
import org.spongycastle.openpgp.PGPEncryptedDataGenerator;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPLiteralData;
import org.spongycastle.openpgp.PGPLiteralDataGenerator;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPPublicKeyRingCollection;
import org.spongycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.spongycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

public class PGPEncrypt {

    public static PGPPublicKey getPublicKey(File publicKeyFile) throws IOException, PGPException {
        InputStream inputStream = new ArmoredInputStream(new FileInputStream(publicKeyFile));
        PGPPublicKeyRingCollection keyRingCollection = new BcPGPPublicKeyRingCollection(inputStream);

        Iterator keyRingCollectionIterator = keyRingCollection.getKeyRings();
        while (keyRingCollectionIterator.hasNext()) {
            PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing) keyRingCollectionIterator.next();

            Iterator publicKeyIterator = publicKeyRing.getPublicKeys();
            while (publicKeyIterator.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) publicKeyIterator.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        return null;
    }

    public static void writeEncrypted(byte[] dataToEncrypt, PGPPublicKey publicKey, File output)
            throws IOException, PGPException {
        String fileName = output.getName();
        FileOutputStream out = new FileOutputStream(output);

        BcPGPDataEncryptorBuilder encryptorBuilder = new BcPGPDataEncryptorBuilder(PGPEncryptedDataGenerator.AES_128);
        encryptorBuilder.setWithIntegrityPacket(true);

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(encryptorBuilder);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));

        OutputStream encryptionOut = encryptedDataGenerator.open(out, new byte[1 << 16]);
        BCPGOutputStream bcpgOut = new BCPGOutputStream(encryptionOut);

        PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
        char literalDataFormatTag = PGPLiteralData.BINARY;

        OutputStream pOut = literalGen.open(bcpgOut, literalDataFormatTag, fileName, new Date(),
                new byte[1 << 16]);
        pOut.write(dataToEncrypt);

        literalGen.close();
        encryptionOut.close();
        out.close();
    }

}
