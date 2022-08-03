/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.in170707dgd17698d;

import java.awt.*;

import java.awt.event.*;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.*;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import static java.lang.System.out;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

/**
 *
 * @author Admin
 */
public class Gui extends JFrame {

    private JFrame f;
    private JPanel panelGenerisanjeKljuceva, panelPrikazPrivatnih, panelEnkripcija, panelDekripcija;
    private JButton btnGenerisanje, btnPrikazPrivatnih, javni, privatni, uveziJavni, uveziPrivatni, btnEnkripcija, btnDekripcija;
    private JButton generisi, dodaj;
    private static JTextField imeText, mejlText, sifraText, uvozText, enkSourceFajl, enkDestFajl, enkIdJavnogKljuca, enkIdPrivatnogKljuca, enkSifra, textPutanja, textSifra;

    boolean isShowingPrivate = true;

    private static ArrayList<PGPPublicKeyRing> prstenJavnih = new ArrayList<PGPPublicKeyRing>();
    private static ArrayList<PGPSecretKeyRing> prstenPivatnih = new ArrayList<PGPSecretKeyRing>();
    private static ArrayList<PGPPublicKeyRing> dodavanjeJavnih = new ArrayList<PGPPublicKeyRing>();

    private ButtonGroup grupa1, grupa2, grupa3Enk;
    private static JRadioButton dsa1024, dsa2048, elGamal1024, elGamal2048, elGamal4096, enk3Des, enkIdea;
    private static JRadioButton enkripcija, potpis, zip, radix;
    private static boolean p = false;

    public PGPKeyRingGenerator createPGPKeyRingGenerator(KeyPair dsaKeyPair, KeyPair elGamalKeyPair, String identity, char[] passphrase) throws Exception {
        PGPKeyPair dsaPgpKeyPair = new PGPKeyPair(PGPPublicKey.DSA, dsaKeyPair, new Date());
        PGPKeyPair elGamalPgpKeyPair = new PGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elGamalKeyPair, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaPgpKeyPair, identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(dsaPgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passphrase));
        keyRingGen.addSubKey(elGamalPgpKeyPair);
        return keyRingGen;
    }

    public static final KeyPair generateElGamalKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public static final KeyPair generateDsaKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    private void setUpPanelForGeneratingKeys() {

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.insets = new Insets(10, 10, 10, 10);

        JLabel naslov;
        naslov = new JLabel("GENERISANJE KLJUCA");
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.gridwidth = 2;
        constraints.anchor = GridBagConstraints.CENTER;
        panelGenerisanjeKljuceva.add(naslov, constraints);

        constraints.gridwidth = 1;
        panelGenerisanjeKljuceva.setBounds(0, 100, 800, 500);
        panelGenerisanjeKljuceva.setVisible(false);

        JLabel imeLabela;
        imeLabela = new JLabel("Ime");
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.gridx = 0;
        constraints.gridy = 1;

        panelGenerisanjeKljuceva.add(imeLabela, constraints);

        imeText = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = 1;

        panelGenerisanjeKljuceva.add(imeText, constraints);

        // constraints.gridy = 1;
        JLabel mejlLabela;
        mejlLabela = new JLabel("Mejl");
        constraints.gridx = 0;
        constraints.gridy = 2;
        panelGenerisanjeKljuceva.add(mejlLabela, constraints);

        mejlText = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = 2;
        panelGenerisanjeKljuceva.add(mejlText, constraints);

        JLabel sifraLabela;
        sifraLabela = new JLabel("Sifra");
        constraints.gridx = 0;
        constraints.gridy = 3;
        panelGenerisanjeKljuceva.add(sifraLabela, constraints);

        sifraText = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = 3;
        panelGenerisanjeKljuceva.add(sifraText, constraints);

        constraints.gridwidth = 2;
        constraints.anchor = GridBagConstraints.WEST;

        dsa1024 = new JRadioButton();
        constraints.gridx = 0;
        constraints.gridy = 4;
        panelGenerisanjeKljuceva.add(dsa1024, constraints);
        JLabel dsa1024Labela;
        dsa1024Labela = new JLabel("DSA 1024");
        constraints.gridx = 1;
        constraints.gridy = 4;
        panelGenerisanjeKljuceva.add(dsa1024Labela, constraints);

        dsa2048 = new JRadioButton();
        constraints.gridx = 0;
        constraints.gridy = 5;
        panelGenerisanjeKljuceva.add(dsa2048, constraints);
        JLabel dsa2048Labela;
        dsa2048Labela = new JLabel("DSA 2048");
        constraints.gridx = 1;
        constraints.gridy = 5;
        panelGenerisanjeKljuceva.add(dsa2048Labela, constraints);

        grupa1 = new ButtonGroup();
        grupa1.add(dsa1024);
        grupa1.add(dsa2048);

        elGamal1024 = new JRadioButton();
        constraints.gridx = 0;
        constraints.gridy = 6;
        panelGenerisanjeKljuceva.add(elGamal1024, constraints);
        JLabel elGamal1024Labela;
        elGamal1024Labela = new JLabel("ElGamal 1024");
        constraints.gridx = 1;
        constraints.gridy = 6;
        panelGenerisanjeKljuceva.add(elGamal1024Labela, constraints);

        elGamal2048 = new JRadioButton();
        constraints.gridx = 0;
        constraints.gridy = 7;
        panelGenerisanjeKljuceva.add(elGamal2048, constraints);
        JLabel elGamal2048Labela;
        elGamal2048Labela = new JLabel("ElGamal 2048");
        constraints.gridx = 1;
        constraints.gridy = 7;
        panelGenerisanjeKljuceva.add(elGamal2048Labela, constraints);

        elGamal4096 = new JRadioButton();
        constraints.gridx = 0;
        constraints.gridy = 8;
        panelGenerisanjeKljuceva.add(elGamal4096, constraints);
        JLabel label9;
        label9 = new JLabel("ElGamal 4096");
        constraints.gridx = 1;
        constraints.gridy = 8;
        panelGenerisanjeKljuceva.add(label9, constraints);

        grupa2 = new ButtonGroup();
        grupa2.add(elGamal1024);
        grupa2.add(elGamal2048);
        grupa2.add(elGamal4096);

        constraints.anchor = GridBagConstraints.CENTER;
        generisi = new JButton("Generisi");
        setUpGenericKeyAction();

        constraints.gridx = 0;
        constraints.gridy = 9;
        panelGenerisanjeKljuceva.add(generisi, constraints);

        f.add(panelGenerisanjeKljuceva);
    }

    public int getElGamalSize(JRadioButton el1024, JRadioButton el2048, JRadioButton el4096) {
        if (el1024.isSelected()) {
            return 1024;
        } else if (el2048.isSelected()) {
            return 2048;
        } else if (el4096.isSelected()) {
            return 4096;
        }
        return 0;
    }

    public int getDSASize(JRadioButton dsa1024, JRadioButton dsa2048) {
        if (dsa1024.isSelected()) {
            return 1024;
        } else if (dsa2048.isSelected()) {
            return 2048;
        }
        return 0;
    }

    public void setUpGenericKeyAction() {
        generisi.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                try {

                    KeyPair dsaKeyPair = generateDsaKeyPair(getDSASize(dsa1024, dsa2048));
                    KeyPair elGa = generateElGamalKeyPair(getElGamalSize(elGamal1024, elGamal2048, elGamal4096));
                    PGPKeyRingGenerator pgpKeyRingGen = createPGPKeyRingGenerator(dsaKeyPair, elGa, imeText.getText() + "<" + mejlText.getText() + ">", sifraText.getText().toCharArray());
                    PGPSecretKeyRing pgpSecKeyRing = pgpKeyRingGen.generateSecretKeyRing();
                    PGPPublicKeyRing pgpPubKeyRing = pgpKeyRingGen.generatePublicKeyRing();

                    prstenJavnih.add(pgpPubKeyRing);
                    System.out.println(pgpPubKeyRing.getPublicKey().getKeyID());
                    prstenPivatnih.add(pgpSecKeyRing);
                    System.out.println(pgpSecKeyRing.getSecretKey().getKeyID());
//                    pgpPubKeyRing.encode(new FileOutputStream("d:\\Users\\Admin\\Desktop\\ZP\\KonacniZp\\pub.pgp"));
//                    pgpSecKeyRing.encode(new FileOutputStream("d:\\Users\\Admin\\Desktop\\ZP\\KonacniZp\\priv.pgp"));
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });
    }

    private void setUpActionButtons() {

        btnPrikazPrivatnih.setBounds(160, 10, 140, 40);
        btnGenerisanje.setBounds(10, 10, 140, 40);
        btnEnkripcija.setBounds(310, 10, 140, 40);
        btnDekripcija.setBounds(460, 10, 140, 40);
        f.setSize(800, 800);
        f.setLayout(null);
        f.add(btnEnkripcija);
        f.add(btnDekripcija);
        f.add(btnPrikazPrivatnih);
        f.add(btnGenerisanje);

    }

    public void setUpActionsForKeyViewing() {

        privatni.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                isShowingPrivate = true;
            }
        });
        javni.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    System.out.println("RADIM");
                    isShowingPrivate = false;
                    f.remove(panelPrikazPrivatnih);
                    panelPrikazPrivatnih.removeAll();
                    setUpPanelForShowPrivateKeys();
                    panelPrikazPrivatnih.setVisible(true);
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });

    }

    public void setUpPanelForDekripcija() {

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.insets = new Insets(10, 10, 10, 10);
        JLabel naslov;
        naslov = new JLabel("Dekripcija");
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.gridwidth = 2;
        constraints.anchor = GridBagConstraints.CENTER;
        panelDekripcija.add(naslov, constraints);
        panelDekripcija.setBounds(0, 100, 800, 300);
        panelDekripcija.setVisible(false);

        JLabel putanja = new JLabel("Putanja do poruke");
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.CENTER;
        panelDekripcija.add(putanja, constraints);

        textPutanja = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = 1;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.CENTER;
        panelDekripcija.add(textPutanja, constraints);

        JLabel sifraDekript = new JLabel("Sifra");
        constraints.gridx = 0;
        constraints.gridy = 2;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.CENTER;
        panelDekripcija.add(sifraDekript, constraints);

        textSifra = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = 2;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.CENTER;
        panelDekripcija.add(textSifra, constraints);

        JButton dekriptuj = new JButton("Dekriptuj");
        constraints.gridx = 0;
        constraints.gridy = 3;
        constraints.gridwidth = 2;
        constraints.anchor = GridBagConstraints.CENTER;
        panelDekripcija.add(dekriptuj, constraints);

        dekriptuj.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    OutputStream outTest = new BufferedOutputStream(new FileOutputStream(textPutanja.getText() + "\\dekriptivano.txt"));
                    InputStream input;
                    input = new BufferedInputStream(new FileInputStream(textPutanja.getText() + "\\enkriptovano.gpg"));
                    if (p == true) {
                        verifikujFajl(input);
                    }

                    byte[] poruka = input.readAllBytes();

                    byte[] dekr = dekriptovanje(poruka);

                    outTest.write(dekr);
                    outTest.close();
                    input.close();
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });

        f.add(panelDekripcija);

    }

    public void setUpPanelForShowPrivateKeys() throws PGPException {

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.insets = new Insets(10, 10, 10, 10);
        JLabel naslov;
        naslov = new JLabel("PRIKAZ " + (isShowingPrivate ? "PRIVATNIH" : "JAVNIH") + " KLJUCEVA");
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.gridwidth = 3;
        constraints.anchor = GridBagConstraints.CENTER;
        panelPrikazPrivatnih.add(naslov, constraints);
        JLabel brisanjeId = new JLabel("ID");
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.gridwidth = 1;
        panelPrikazPrivatnih.add(brisanjeId, constraints);
        JTextField brisanjeText = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = 1;
        panelPrikazPrivatnih.add(brisanjeText, constraints);
        JButton btnBrisanje = new JButton("Obrisi");
        constraints.gridx = 2;
        constraints.gridy = 1;
        panelPrikazPrivatnih.add(btnBrisanje, constraints);
        JButton btnIzvoz = new JButton("Izvezi");
        constraints.gridx = 3;
        constraints.gridy = 1;
        panelPrikazPrivatnih.add(btnIzvoz, constraints);
        JTextField brisanjeSifraText = new JTextField(30);
        int yBrisanjePrivatnih = 2;
        if (isShowingPrivate) {
            JLabel brisanjeSifra = new JLabel("Sifra");
            constraints.gridx = 0;
            constraints.gridy = yBrisanjePrivatnih;
            constraints.gridwidth = 1;
            panelPrikazPrivatnih.add(brisanjeSifra, constraints);

            constraints.gridx = 1;
            constraints.gridy = yBrisanjePrivatnih;
            constraints.gridwidth = 2;
            constraints.anchor = GridBagConstraints.WEST;
            panelPrikazPrivatnih.add(brisanjeSifraText, constraints);

            constraints.gridwidth = 1;
            constraints.anchor = GridBagConstraints.NORTH;
            yBrisanjePrivatnih++;
        }
        int visinaPanela = 300;
        constraints.gridwidth = 1;
        panelPrikazPrivatnih.setBounds(0, 100, 800, visinaPanela);
        panelPrikazPrivatnih.setVisible(false);
        JLabel prikazi;
        prikazi = new JLabel("Prikazi:");
        constraints.gridx = 0;
        constraints.gridy = yBrisanjePrivatnih;
        constraints.gridwidth = 1;
        panelPrikazPrivatnih.add(prikazi, constraints);
        privatni = new JButton("Privatni");
        constraints.gridx = 1;
        constraints.gridy = yBrisanjePrivatnih;
        panelPrikazPrivatnih.add(privatni, constraints);
        javni = new JButton("Javni");
        constraints.gridx = 2;
        constraints.gridy = yBrisanjePrivatnih;
        panelPrikazPrivatnih.add(javni, constraints);
        yBrisanjePrivatnih++;
        JLabel uveziLabela;
        uveziLabela = new JLabel("Fajl:");
        constraints.gridx = 0;
        constraints.gridy = yBrisanjePrivatnih;
        constraints.gridwidth = 1;
        panelPrikazPrivatnih.add(uveziLabela, constraints);
        uvozText = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = yBrisanjePrivatnih;
        constraints.gridwidth = 2;
        constraints.anchor = GridBagConstraints.WEST;
        uvozText.setText("Ovde ide ime fajla");
        panelPrikazPrivatnih.add(uvozText, constraints);
        yBrisanjePrivatnih++;
        constraints.anchor = GridBagConstraints.NORTH;
        JLabel prikaziUvoz;
        prikaziUvoz = new JLabel("Uvezi:");
        constraints.gridx = 0;
        constraints.gridy = yBrisanjePrivatnih;
        constraints.gridwidth = 1;
        panelPrikazPrivatnih.add(prikaziUvoz, constraints);
        uveziPrivatni = new JButton("Privatni");
        constraints.gridx = 1;
        constraints.gridy = yBrisanjePrivatnih;
        panelPrikazPrivatnih.add(uveziPrivatni, constraints);
        uveziJavni = new JButton("Javni");
        constraints.gridx = 2;
        constraints.gridy = yBrisanjePrivatnih;
        panelPrikazPrivatnih.add(uveziJavni, constraints);
        yBrisanjePrivatnih++;
        constraints.gridwidth = 1;
        JLabel idLabela;
        idLabela = new JLabel("ID");
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.gridx = 0;
        constraints.gridy = yBrisanjePrivatnih;
        panelPrikazPrivatnih.add(idLabela, constraints);
        JLabel imeLabela;
        imeLabela = new JLabel("Ime");
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.gridx = 1;
        constraints.gridy = yBrisanjePrivatnih;
        panelPrikazPrivatnih.add(imeLabela, constraints);
        JLabel emailLabela;
        emailLabela = new JLabel("Email");
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.gridx = 2;
        constraints.gridy = yBrisanjePrivatnih;
        panelPrikazPrivatnih.add(emailLabela, constraints);
        int y = ++yBrisanjePrivatnih;
        System.out.println(prstenPivatnih.size());
        int size = isShowingPrivate ? prstenPivatnih.size() : prstenJavnih.size();
        for (int i = 0; i < size; i++) {

            visinaPanela += 50;
            panelPrikazPrivatnih.setBounds(0, 100, 800, visinaPanela);

            String id = (isShowingPrivate ? prstenPivatnih.get(i).getSecretKey().getKeyID() : prstenJavnih.get(i).getPublicKey().getKeyID()) + "";

            System.out.println("Usao");
            JLabel labelaId = new JLabel(id);

            constraints.anchor = GridBagConstraints.NORTH;
            constraints.gridx = 0;
            constraints.gridy = y;
            panelPrikazPrivatnih.add(labelaId, constraints);

            String ime = (isShowingPrivate ? prstenPivatnih.get(i).getSecretKey().getUserIDs().next().toString().split("<")[0] : prstenJavnih.get(i).getPublicKey().getUserIDs().next().toString().split("<")[0]) + "";
            JLabel labelaIme = new JLabel(ime);

            constraints.anchor = GridBagConstraints.NORTH;
            constraints.gridx = 1;
            constraints.gridy = y;
            panelPrikazPrivatnih.add(labelaIme, constraints);

            String email = (isShowingPrivate ? prstenPivatnih.get(i).getSecretKey().getUserIDs().next().toString().split("<")[1].split(">")[0] : prstenJavnih.get(i).getPublicKey().getUserIDs().next().toString().split("<")[1].split(">")[0]) + "";
            JLabel labelaEmail = new JLabel(email);
            constraints.anchor = GridBagConstraints.NORTH;
            constraints.gridx = 2;
            constraints.gridy = y;
            panelPrikazPrivatnih.add(labelaEmail, constraints);
            y++;
        }
        uveziJavni.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    System.out.println("Uvozim Javni");

                    f.remove(panelPrikazPrivatnih);
                    panelPrikazPrivatnih.removeAll();

                    uveziJavni();

                    setUpPanelForShowPrivateKeys();
                    panelPrikazPrivatnih.setVisible(true);
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });
        uveziPrivatni.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    System.out.println("Uvozim Privatni");

                    f.remove(panelPrikazPrivatnih);
                    panelPrikazPrivatnih.removeAll();

                    uveziPrivatni();

                    setUpPanelForShowPrivateKeys();
                    panelPrikazPrivatnih.setVisible(true);
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });
        privatni.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                try {
                    isShowingPrivate = true;
                    f.remove(panelPrikazPrivatnih);
                    panelPrikazPrivatnih.removeAll();
                    setUpPanelForShowPrivateKeys();
                    panelPrikazPrivatnih.setVisible(true);
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        javni.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    System.out.println("RADIM");
                    isShowingPrivate = false;
                    f.remove(panelPrikazPrivatnih);
                    panelPrikazPrivatnih.removeAll();
                    setUpPanelForShowPrivateKeys();
                    panelPrikazPrivatnih.setVisible(true);
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        btnBrisanje.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    System.out.println("Sebrem");

                    f.remove(panelPrikazPrivatnih);
                    panelPrikazPrivatnih.removeAll();

                    if (isShowingPrivate) {
                        try {
                            obrisiPrivatni(brisanjeText.getText(), brisanjeSifraText.getText());
                        } catch (IOException ex) {
                            Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    } else {
                        obrisiJavni(brisanjeText.getText());
                    }

                    System.out.println("size mi je " + prstenJavnih.size());

                    setUpPanelForShowPrivateKeys();
                    panelPrikazPrivatnih.setVisible(true);
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });
        btnIzvoz.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    System.out.println("Zvozim");

                    f.remove(panelPrikazPrivatnih);
                    panelPrikazPrivatnih.removeAll();

                    if (isShowingPrivate) {
                        izveziPrivatni(brisanjeText.getText());
                    } else {
                        izveziJavni(brisanjeText.getText());
                    }

                    System.out.println("size mi je " + prstenJavnih.size());

                    setUpPanelForShowPrivateKeys();
                    panelPrikazPrivatnih.setVisible(true);
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });
        f.setSize(799, 799);
        f.setSize(800, 800);
        f.add(panelPrikazPrivatnih);

    }

    void uveziJavni() throws IOException, PGPException {
        InputStream inputStream = null;
        File f = new File(uvozText.getText() + "");
        try {

            if (!f.exists()) {
                System.out.println("To sto oces nepostoji poz");
                return;
            }
            inputStream = new FileInputStream(f);

            PGPPublicKeyRing novi = new PGPPublicKeyRing(PGPUtil.getDecoderStream(inputStream), new JcaKeyFingerprintCalculator());
            for (int i = 0; i < prstenJavnih.size(); i++) {
                if (prstenJavnih.get(i).getPublicKey().getKeyID() == novi.getPublicKey().getKeyID()) {
                    System.out.println("VEc postoji");
                    return;
                }
            }
            prstenJavnih.add(novi);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (f.exists()) {
                    inputStream.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    void uveziPrivatni() throws PGPException, IOException {
        File f = new File(uvozText.getText() + "");
        InputStream inputStream = null;
        try {

            if (!f.exists()) {
                System.out.println("To sto oces nepostoji poz");
                return;
            }

            inputStream = new FileInputStream(f);
            PGPSecretKeyRing novi = new PGPSecretKeyRing(PGPUtil.getDecoderStream(inputStream), new JcaKeyFingerprintCalculator());
            for (int i = 0; i < prstenPivatnih.size(); i++) {
                if (prstenPivatnih.get(i).getPublicKey().getKeyID() == novi.getPublicKey().getKeyID()) {
                    System.out.println("VEc postoji");
                    return;
                }
            }
            prstenPivatnih.add(novi);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (f.exists()) {
                    inputStream.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

    }

    void izveziPrivatni(String id) {

        for (int i = 0; i < prstenPivatnih.size(); i++) {
            if (id.equals(prstenPivatnih.get(i).getSecretKey().getKeyID() + "")) {
                try {
                    PGPSecretKeyRing pgpSecKeyRingRing = prstenPivatnih.get(i);
                    pgpSecKeyRingRing.encode(new FileOutputStream(uvozText.getText() + "\\privatni.asc"));
                    System.out.println("Izveo Privatni");
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }

    }

    void izveziJavni(String id) {

        for (int i = 0; i < prstenJavnih.size(); i++) {
            if (id.equals(prstenJavnih.get(i).getPublicKey().getKeyID() + "")) {
                try {
                    PGPPublicKeyRing pgpPubKeyRing = prstenJavnih.get(i);
                    pgpPubKeyRing.encode(new FileOutputStream(uvozText.getText() + "javni.asc"));
                    System.out.println("Izveo Javni");
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }

    }

    void obrisiPrivatni(String id, String sifra) throws IOException {

        for (int i = 0; i < prstenPivatnih.size(); i++) {
            if (id.equals(prstenPivatnih.get(i).getSecretKey().getKeyID() + "")) {

                try {
                    char[] passphrase = sifra.toCharArray();
                    if (prstenPivatnih.get(i).getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase)) != null) {
                        prstenPivatnih.remove(i);
                        System.out.println("OBRISAN PRIVATNI KLJUC SA ID = " + id);
                        return;
                    }
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        System.out.println("NEPOSTOJI TAJ KLJUC SA ID = " + id);

    }

    void obrisiJavni(String id) {

        for (int i = 0; i < prstenJavnih.size(); i++) {
            if (id.equals(prstenJavnih.get(i).getPublicKey().getKeyID() + "")) {
                prstenJavnih.remove(i);
                System.out.println("OBRISAN JAVNI KLJUC SA ID = " + id);
                return;
            }
        }
        System.out.println("NEPOSTOJI TAJ KLJUC SA ID = " + id);
    }

    void setPanelsFalse() {

        panelGenerisanjeKljuceva.setVisible(false);
        panelPrikazPrivatnih.setVisible(false);
        panelEnkripcija.setVisible(false);
        panelDekripcija.setVisible(false);

    }

    public void setUpPanelForEnkripcija() {

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.insets = new Insets(10, 10, 10, 10);
        JLabel naslov;
        naslov = new JLabel("ENKRIPCIJA");
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.gridwidth = 3;
        constraints.anchor = GridBagConstraints.CENTER;
        panelEnkripcija.add(naslov, constraints);

        panelEnkripcija.setBounds(0, 100, 800, 500);
        panelEnkripcija.setVisible(false);

        JLabel porukaLabela = new JLabel("Fajl za enkripciju");
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(porukaLabela, constraints);

        enkSourceFajl = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = 1;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(enkSourceFajl, constraints);

        JLabel idJavnog = new JLabel("ID javnog kljuca");
        constraints.gridx = 0;
        constraints.gridy = 2;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(idJavnog, constraints);

        enkIdJavnogKljuca = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = 2;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(enkIdJavnogKljuca, constraints);

        dodaj = new JButton("Dodaj");
        constraints.gridx = 2;
        constraints.gridy = 2;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(dodaj, constraints);

        JLabel idPrivatnog = new JLabel("ID privatnog kljuca");
        constraints.gridx = 0;
        constraints.gridy = 3;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(idPrivatnog, constraints);

        enkIdPrivatnogKljuca = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = 3;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(enkIdPrivatnogKljuca, constraints);

        JLabel sifra = new JLabel("Sifra privatnog");
        constraints.gridx = 0;
        constraints.gridy = 4;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(sifra, constraints);

        enkSifra = new JTextField(30);
        constraints.gridx = 1;
        constraints.gridy = 4;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(enkSifra, constraints);

        enk3Des = new JRadioButton("3DES");
        constraints.gridx = 0;
        constraints.gridy = 5;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(enk3Des, constraints);

        enkIdea = new JRadioButton("IDEA");
        constraints.gridx = 1;
        constraints.gridy = 5;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(enkIdea, constraints);

        grupa3Enk = new ButtonGroup();
        grupa3Enk.add(enk3Des);
        grupa3Enk.add(enkIdea);

        enkripcija = new JRadioButton("Enkripcija");
        constraints.gridx = 0;
        constraints.gridy = 6;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(enkripcija, constraints);

        potpis = new JRadioButton("Potpis");
        constraints.gridx = 0;
        constraints.gridy = 7;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(potpis, constraints);

        zip = new JRadioButton("Zip");
        constraints.gridx = 0;
        constraints.gridy = 8;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(zip, constraints);

        radix = new JRadioButton("Radix");
        constraints.gridx = 0;
        constraints.gridy = 9;
        constraints.gridwidth = 1;
        constraints.anchor = GridBagConstraints.WEST;
        panelEnkripcija.add(radix, constraints);

        JButton enkriptuj = new JButton("Enkriptuj");
        constraints.gridx = 0;
        constraints.gridy = 10;
        constraints.gridwidth = 3;
        constraints.anchor = GridBagConstraints.NORTH;
        panelEnkripcija.add(enkriptuj, constraints);

        dodaj.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.out.println("Usao da dodam");
                for (int i = 0; i < prstenJavnih.size(); i++) {
                    if (enkIdJavnogKljuca.getText().equals(prstenJavnih.get(i).getPublicKey().getKeyID() + "")) {

                        dodavanjeJavnih.add(prstenJavnih.get(i));
                        System.out.println("Dodao sam " + prstenJavnih.get(i).getPublicKey().getKeyID());
                    }
                }
            }
        });
        //Radi lepo da registruje da ne moze potpis da se verifikuje

        enkriptuj.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {

                    OutputStream out = new BufferedOutputStream(new FileOutputStream(enkSourceFajl.getText() + "\\enkriptovano.gpg"));
//                    Kleopatra ako nema potpisa trazi sifru da dekriptuje ali ako ima potpisa i ona misli da je validan onda na keca
//                            ga depriptuje, a ako nema potpisa onda ti da kao upozorenje da niko nije potpisao
                    if (true) {
                        // Znaci potpis kada radis treba ti onaj prvi kljuc sto smo videli iz kleopatre da prikaze kad klikes vise detalja
                        p = false;
                        PGPSecretKey kljuc23 = null;

                        for (int i = 0; i < prstenPivatnih.size(); i++) {
                            if (enkIdPrivatnogKljuca.getText().equals(prstenPivatnih.get(i).getSecretKey().getKeyID() + "")) {

                                java.util.Iterator<PGPSecretKey> upomoc123 = prstenPivatnih.get(i).getSecretKeys();
                                kljuc23 = upomoc123.next();
                                System.out.println("Dodao sam " + prstenJavnih.get(i).getPublicKey().getKeyID());
                            }
                        }
//                        java.util.Iterator<PGPSecretKey> upomoc123 = prstenPivatnih.get(0).getSecretKeys();
//                        kljuc23 = upomoc123.next();
                        if (potpis.isSelected()) {
                            potpisiFajl(enkSourceFajl.getText() + "\\poruka.txt", kljuc23, out, enkSifra.getText().toCharArray(), true);
                        }
//                        Kriptovanje odmah ispod potisa zabode poruku i ono kompresija se iskljuci na nacin tako sto samo 
//                                moze da se izabere da ne bude kompresovan a ne da se brise kod
//                                        Kod ovoga se bira onaj ispod kljuc sto smo videli u kleopatri
                        PGPPublicKey kljuc1 = null;
                        InputStream input = new BufferedInputStream(new FileInputStream(enkSourceFajl.getText() + "\\poruka.txt"));
                        java.util.Iterator<PGPPublicKey> upomoc13 = prstenJavnih.get(0).getPublicKeys();
                        upomoc13.next();
                        kljuc1 = upomoc13.next();
                        byte[] poruka = input.readAllBytes();
                        poruka = kriptovanje(poruka, kljuc1, "poruka.txt", 1, radix.isSelected() ? true : false);
                        out.write(poruka);
                        out.close();
                        //Opet se koristi onaj kljuc iznad
//                        PGPPublicKey kljuc13 = null;
//                        java.util.Iterator<PGPPublicKey> upomoc133 = prstenJavnih.get(0).getPublicKeys();
//                        //upomoc133.next();
//                        kljuc13 = upomoc133.next();
//                        InputStream input23 = new BufferedInputStream(new FileInputStream(enkSourceFajl.getText() + "\\enkriptovano.gpg"));
//                        verifikujFajl(input23, kljuc13);
                        //Cak iako se dekriptuje ostavis onaj kod za kompresiju i on sam skonta, i cak iako iskljucis onaj armor on sam skonta
                        //Izgleda da dekripcija traje neko vreme pa se onaj fajl ne promeni odmah
//                        PGPSecretKey kljuc = null;
//                        java.util.Iterator<PGPSecretKey> upomoc1 = prstenPivatnih.get(0).getSecretKeys();
//                        kljuc = upomoc1.next();
//                        kljuc = upomoc1.next();
//                        byte[] dekr = dekriptovanje(poruka, kljuc);
//
//                        outTest.write(dekr);
                        // outTest.close();
                        input.close();
                    }
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (GeneralSecurityException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });

        f.setSize(799, 799);
        f.setSize(800, 800);
        f.add(panelEnkripcija);

    }

    private static void verifikujFajl(
            InputStream in)
            throws Exception {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

        PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();

        PGPOnePassSignature ops = p1.get(0);

        PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

        InputStream dIn = p2.getInputStream();
        int ch;

        PGPPublicKey key = null;

        for (int i = 0; i < prstenPivatnih.size(); i++) {
            java.util.Iterator<PGPPublicKey> upomoc1 = prstenJavnih.get(i).getPublicKeys();
            key = upomoc1.next();
            if (ops.getKeyID() == key.getKeyID()) {
                break;
            } else {
                key = null;
            }

        }
        if (key == null) {
            throw new IllegalArgumentException("Nema kljuca javnog baki");
        }

        FileOutputStream out = new FileOutputStream(p2.getFileName());

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

        while ((ch = dIn.read()) >= 0) {
            ops.update((byte) ch);
            out.write(ch);
        }

        out.close();

        PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

        if (ops.verify(p3.get(0))) {
            System.out.println("verifikovan potpis");
        } else {
            System.out.println("potpis nevalja");
        }
        p = false;
    }

    private static void potpisiFajl(
            String fileName,
            PGPSecretKey keyIn,
            OutputStream out,
            char[] pass,
            boolean armor)
            throws IOException, PGPException, SignatureException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        PGPSecretKey pgpSec = keyIn;
        PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
                PGPCompressedData.ZLIB);

        BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(out));

        sGen.generateOnePassVersion(false).encode(bOut);

        File file = new File(fileName);
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
        FileInputStream fIn = new FileInputStream(file);
        int ch;

        while ((ch = fIn.read()) >= 0) {
            lOut.write(ch);
            sGen.update((byte) ch);
        }

        lGen.close();

        sGen.generate().encode(bOut);

        cGen.close();

        if (armor) {
            out.close();
        }
        p = true;
    }

    public static byte[] dekriptovanje(
            byte[] encrypted)
            throws IOException, PGPException, NoSuchProviderException {
        InputStream in = new ByteArrayInputStream(encrypted);

        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();

        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        PGPPublicKeyEncryptedData pbe = (PGPPublicKeyEncryptedData) enc.get(0);

        Iterator it = enc.getEncryptedDataObjects();
        PGPSecretKey pgpSecKey = null;
        PBESecretKeyDecryptor secretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(textSifra.getText().toCharArray());

        pbe = (PGPPublicKeyEncryptedData) it.next();

        for (int i = 0; i < prstenPivatnih.size(); i++) {
            System.out.println(pbe.getKeyID());
            java.util.Iterator<PGPSecretKey> upomoc1 = prstenPivatnih.get(i).getSecretKeys();
            pgpSecKey = upomoc1.next();
            pgpSecKey = upomoc1.next();
            if (pbe.getKeyID() == pgpSecKey.getKeyID()) {
                break;
            } else {
                pgpSecKey = null;
            }
        }
        dodavanjeJavnih = null;
        dodavanjeJavnih = new ArrayList<PGPPublicKeyRing>();
        System.out.println(pgpSecKey.getKeyID());
        if (pgpSecKey == null) {
            throw new IllegalArgumentException("Nema kljuca baki");
        }
        PGPPrivateKey sKey = pgpSecKey.extractPrivateKey(secretKeyDecryptor);

        if (sKey == null) {
            throw new IllegalArgumentException("tajni kljuc nije nadjen");
        }

        InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

        PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();

        pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

        PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

        return Streams.readAll(ld.getInputStream());
    }

    public static byte[] kriptovanje(
            byte[] clearData,
            PGPPublicKey passPhrase,
            String fileName,
            int algorithm,
            boolean armor)
            throws IOException, PGPException, NoSuchProviderException {
        if (fileName == null) {
            fileName = PGPLiteralData.CONSOLE;
        }

        byte[] compressedData = compress(clearData, fileName, zip.isSelected() ? CompressionAlgorithmTags.ZIP : CompressionAlgorithmTags.UNCOMPRESSED);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = bOut;
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
        int izbor = 0;
        if (enk3Des.isEnabled()) {
            izbor = PGPEncryptedData.TRIPLE_DES;
        } else if (enkIdea.isEnabled()) {
            izbor = PGPEncryptedData.IDEA;
        }

        if (enkripcija.isSelected()) {
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(izbor).setSecureRandom(new SecureRandom()).setProvider("BC"));
            //Ovde se dodaju kljucevi
            for (int i = 0; i < dodavanjeJavnih.size(); i++) {
                java.util.Iterator<PGPPublicKey> upomoc13 = dodavanjeJavnih.get(i).getPublicKeys();
                upomoc13.next();
                PGPPublicKey kljuc1 = upomoc13.next();
                encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(kljuc1).setProvider("BC"));
            }
            OutputStream encOut = encGen.open(out, compressedData.length);

            encOut.write(compressedData);
            encOut.close();
        } else {
            out.write(compressedData);
        }

        if (armor) {
            out.close();
        }

        return bOut.toByteArray();
    }

    private static byte[] compress(byte[] clearData, String fileName, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        OutputStream cos = comData.open(bOut);

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = lData.open(cos,
                PGPLiteralData.BINARY,
                fileName,
                clearData.length,
                new Date()
        );

        pOut.write(clearData);
        pOut.close();

        comData.close();

        return bOut.toByteArray();
    }

    public Gui() throws PGPException {

        f = new JFrame("SetBounds Example");
        panelGenerisanjeKljuceva = new JPanel(new GridBagLayout());
        panelPrikazPrivatnih = new JPanel(new GridBagLayout());
        panelEnkripcija = new JPanel(new GridBagLayout());
        btnGenerisanje = new JButton("Generisanje");
        btnPrikazPrivatnih = new JButton("Prikaz");
        btnEnkripcija = new JButton("Enkripcija");
        btnDekripcija = new JButton("Dekripcija");
        panelDekripcija = new JPanel(new GridBagLayout());

        setUpActionButtons();

        btnGenerisanje.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                setPanelsFalse();
                panelGenerisanjeKljuceva.setVisible(true);
            }
        });

        btnPrikazPrivatnih.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    setPanelsFalse();
                    f.remove(panelPrikazPrivatnih);
                    panelPrikazPrivatnih.removeAll();
                    setUpPanelForShowPrivateKeys();
                    panelPrikazPrivatnih.setVisible(true);
                } catch (PGPException ex) {
                    Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        btnEnkripcija.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.out.println("Dugme radi");
                setPanelsFalse();
                f.remove(panelEnkripcija);
                panelEnkripcija.removeAll();
                setUpPanelForEnkripcija();
                panelEnkripcija.setVisible(true);
            }
        });
        btnDekripcija.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                setPanelsFalse();
                f.remove(panelDekripcija);
                panelDekripcija.removeAll();
                setUpPanelForDekripcija();
                panelDekripcija.setVisible(true);
            }
        });

        setUpPanelForGeneratingKeys();
        setUpPanelForShowPrivateKeys();
        setUpActionsForKeyViewing();
        setUpPanelForEnkripcija();
        setUpPanelForDekripcija();

        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        f.setLocationRelativeTo(null);
        f.setVisible(true);

    }

    public static void main(String[] args) throws FileNotFoundException, IOException, PGPException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        Gui a = new Gui();

    }

}
