
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

public class ClientCP1withAP {

    public static void main(String[] args) {
        String responsemessage = null;
        String filename = null;
        int numberoffiles = args.length;
        byte[] message = null;

        String serverAddress = "localhost";
        int port = 4321;
        //if (args.length > 2) port = Integer.parseInt(args[2]);

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        long timeStarted = System.nanoTime();


        try {

            System.out.println("Establishing connection to server...");

            //get public key from the CA
            InputStream fis = new FileInputStream("D:\\GitHub\\PA2\\cacsertificate.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate) cf.generateCertificate(fis);
            PublicKey key = CAcert.getPublicKey();

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            System.out.println("Asking for authentication...");

            // asking to prove its identity, with writeInt
            String initialisationmessage = "123456";
            toServer.writeInt(2);
            toServer.writeInt(initialisationmessage.getBytes().length);
            toServer.write(initialisationmessage.getBytes());

            // wait for the server's response before proceeding
            while (responsemessage == null) {
                if (fromServer.readInt() == 2) {
                    System.out.println("Receiving message from the server");
                    numBytes = fromServer.readInt();
                    message = new byte[numBytes];
                    fromServer.readFully(message, 0, numBytes);
                    responsemessage = new String(message);
                    System.out.println("Message successfully received");
                }
            }

            // Asking the Server for their certificate signed by the CA
            String CAmessage = "Please provide your signed CA";
            System.out.println("Asking for the CA now");
            toServer.writeInt(2);
            toServer.writeInt(CAmessage.getBytes().length);
            toServer.write(CAmessage.getBytes());

            //proceed only when the Server has provided the CA
            boolean CAprovided = true;
            while(CAprovided){
                int packetType = fromServer.readInt();
                if(packetType==0){
                    numBytes = fromServer.readInt();
                    byte [] filename1 = new byte[numBytes];
                    fromServer.readFully(filename1, 0, numBytes);
                    fileOutputStream = new FileOutputStream("recv_"+new String(filename1, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                }else if (packetType == 1) {
                    numBytes = fromServer.readInt();
                    byte [] block = new byte[numBytes];
                    fromServer.readFully(block, 0, numBytes);
                    if (numBytes > 0){
                        bufferedFileOutputStream.write(block, 0, numBytes);
                    }
                    if (numBytes < 117) {
                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                        CAprovided = false;
                    }

                }
            }
            // the public key from the certificate of the Server, and verify it
            InputStream fileInputStream1 = new FileInputStream("recv_certificate_1004448.crt");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate ServerCertificate = (X509Certificate) (certificateFactory.generateCertificate(fileInputStream1));
            ServerCertificate.verify(key);
            PublicKey publicKey = ServerCertificate.getPublicKey();

            // decrypt the message sent by the server, and check if it is correct or not
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] decryptedmessage = cipher.doFinal(message);
            String messagetocheck = new String(decryptedmessage);
            System.out.println("The decrypted message sent by the server is " + messagetocheck);

            // if it is correct, continue to send the files to the server
            if (messagetocheck.equals("123456")) {
                System.out.println("The message is correct and identical");
                toServer.writeInt(11);
                toServer.writeInt(numberoffiles);

                System.out.println("Sending File");
                Cipher rsacipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsacipher.init(Cipher.ENCRYPT_MODE, publicKey);
                byte[] encryptedblock = null;
                byte[] fromFileBuffer = new byte[117];

                // encrypt the files with the servers' public key before sending it to the server, first filename, then the file
                for (int i=0; i<numberoffiles; i++){
                    filename = args[i];
                    encryptedblock = rsacipher.doFinal(filename.getBytes());

                    toServer.writeInt(0);
                    toServer.writeInt(encryptedblock.length);
                    toServer.write(encryptedblock);

                    //open the file
                    fileInputStream = new FileInputStream("D:\\GitHub\\PA2\\PA2\\"+filename);
                    bufferedFileInputStream = new BufferedInputStream(fileInputStream);

                    //send file
                    for (boolean fileEnded = false; !fileEnded;) {
                        numBytes = bufferedFileInputStream.read(fromFileBuffer);
                        encryptedblock = rsacipher.doFinal(fromFileBuffer);
                        fileEnded = numBytes < 117;
                        if (fileEnded) {
                            System.out.println("Reached end of file "+(i+1));
                        }
                        toServer.writeInt(1);
                        toServer.writeInt(numBytes); // send num of bytes of decrypted
                        toServer.writeInt(encryptedblock.length); // send num of bytes of encrypted
                        toServer.write(encryptedblock);
                    }
                }
                System.out.println("All the files has been transferred");
                System.out.println("Closing Connection");
                bufferedFileInputStream.close();
                fileInputStream.close();

            }
            else{
                System.out.println("Closing connection");
                clientSocket.close();
            }

        }catch (Exception e) {e.printStackTrace();}

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
    }


}