import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLOutput;

import javax.crypto.Cipher;

public class ServerCP1withAP {


    public static void main(String[] args) throws Exception {
        PrivateKey privateKey = PrivateKeyReader.get("private_key.der");
        PublicKey publicKey = PublicKeyReader.get("public_key.der");
        byte [] decryptedblock = null;

        int filesreceived =0;
        int numberoffiles =0;

        int port = 4321;

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    System.out.println("Receiving file...");
                    int numBytes = fromClient.readInt();
                    byte [] filename = new byte[numBytes];
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);
                    Cipher rsacipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsacipher.init(Cipher.DECRYPT_MODE, privateKey);
                    decryptedblock = rsacipher.doFinal(filename);
                    String decryptedFileName = new String(decryptedblock);
                    fileOutputStream = new FileOutputStream("recv_"+decryptedFileName);
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {
                    int numBytes = fromClient.readInt(); // get num of bytes of decrypted
                    int encryptedBytes = fromClient.readInt(); // get num of bytes of encrypted
                    byte [] block = new byte[encryptedBytes];
                    fromClient.readFully(block, 0, encryptedBytes);
                    Cipher rsacipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsacipher.init(Cipher.DECRYPT_MODE,privateKey);

                    if (numBytes > 0) {
                        decryptedblock = rsacipher.doFinal(block);
                        bufferedFileOutputStream.write(decryptedblock, 0, numBytes);}

                    if (numBytes < 117 && filesreceived < numberoffiles) {
                        filesreceived++;
                        System.out.println("File "+filesreceived+" received fully, closing...");
                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();}

                    if (filesreceived == numberoffiles){
                        System.out.println("Closing connection...");
                        toClient.writeInt(10);
                        fromClient.close();
                        toClient.close();
                        connectionSocket.close();}
                    }

                // If the packet is for asking for handshake
                else if (packetType ==2){
                        int numBytes = fromClient.readInt();
                        byte[] block = new byte[numBytes];
                        fromClient.readFully(block, 0, numBytes);
                        System.out.println(new String(block));


                        Cipher rsacipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        rsacipher.init(Cipher.ENCRYPT_MODE, privateKey);
                        byte[] encryptedblock = rsacipher.doFinal(block);
                        System.out.println("Sending the encrypted message");

                        toClient.writeInt(2);
                        toClient.writeInt(encryptedblock.length);
                        toClient.write(encryptedblock);


                        String message = null;
                        while(message == null){
                        // Send the filename
                        if(fromClient.readInt() ==2){
                            numBytes = fromClient.readInt();
                            block = new byte[numBytes];
                            fromClient.readFully(block,0,numBytes);
                            System.out.println(new String(block));

                            String filename = "certificate_1004448.crt";
                            toClient.writeInt(0);
                            toClient.writeInt(filename.getBytes().length);
                            toClient.write(filename.getBytes());

                        // open the file
                        FileInputStream fileInputStream = new FileInputStream(filename);
                        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);

                        byte[] fromFileBuffer = new byte[117];

                        //send the file
                        for (boolean fileEnded = false; !fileEnded;) {
                            numBytes = bufferedInputStream.read(fromFileBuffer);
                            fileEnded = numBytes < 117;

                            toClient.writeInt(1);
                            toClient.writeInt(numBytes);
                            toClient.write(fromFileBuffer);
                            toClient.flush();
                        }
                        bufferedInputStream.close();
                        fileInputStream.close();
                        System.out.println("Certificate sent");

                            message = "Cert is sent";
                            toClient.writeInt(2);
                            toClient.writeInt(message.getBytes().length);
                            toClient.write(message.getBytes());
                            break;
                        }

                }}
                    else if (packetType==11) {
                    numberoffiles = fromClient.readInt();
                    System.out.println("Number of files: " + numberoffiles);
                }
                }

        } catch (Exception e) {e.printStackTrace();}
    }
}