package com.android.camera.crypto;

import java.io.File;
import java.io.IOException;

import android.os.Environment;

import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPPublicKey;

public class CryptoController {
    private static CryptoController instance;

    public static CryptoController getInstance() {
        if (instance == null) {
            instance = new CryptoController();
        }

        return instance;
    }


    private final PGPPublicKey publicKey;

    private CryptoController() {
        File openKeychainFolder = new File(Environment.getExternalStorageDirectory(), "OpenKeychain");
        File publicKeyFile = new File(openKeychainFolder, "cryptocam.asc");

        PGPPublicKey key = null;
        try {
            key = PGPEncrypt.getPublicKey(publicKeyFile);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
        publicKey = key;
    }

    public boolean writeEncrypted(byte[] dataToEncrypt, File output) throws IOException, PGPException {
        if (publicKey == null) {
            System.out.println("No public key loaded");
            return false;
        }

        System.out.println("Write encrypted data to: " + output.getAbsolutePath());
        PGPEncrypt.writeEncrypted(dataToEncrypt, publicKey, output);

        return true;
    }
}
