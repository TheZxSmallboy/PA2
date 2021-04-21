import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class ServerCP2withAP {

        public static void main(String[] args) throws Exception {
            PrivateKey privateKey = PrivateKeyReader.get("/Users/zixuan/StudioProjects/ProgrammingAssignment2/private_key.der");
            PublicKey publicKey = PublicKeyReader.get("/Users/zixuan/StudioProjects/ProgrammingAssignment2/public_key.der");
            byte [] decryptedblock = null;

            int filesreceived =0;
            int numberoffiles =0;

            int port = 4321;
            if (args.length > 0) port = Integer.parseInt(args[0]);

            ServerSocket welcomeSocket = null;
            Socket connectionSocket = null;
            DataOutputStream toClient = null;
            DataInputStream fromClient = null;

            FileOutputStream fileOutputStream = null;
            BufferedOutputStream bufferedFileOutputStream = null;
            SecretKey symmetryKey = null;

            try {
                welcomeSocket = new ServerSocket(port);
                connectionSocket = welcomeSocket.accept();
                fromClient = new DataInputStream(connectionSocket.getInputStream());
                toClient = new DataOutputStream(connectionSocket.getOutputStream());

                while (!connectionSocket.isClosed()) {

                    int packetType = fromClient.readInt();
                    System.out.println(packetType);

                    // If the packet is for transferring the filename
                    if (packetType == 0) {

                        System.out.println("Receiving file...");
                        int numBytes = fromClient.readInt();
                        byte [] filename = new byte[numBytes];
                        // Must use read fully!
                        // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                        fromClient.readFully(filename, 0, numBytes);

                        Cipher symmetryCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        symmetryCipher.init(Cipher.DECRYPT_MODE, symmetryKey);
                        decryptedblock = symmetryCipher.doFinal(filename);

                        fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
                        bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                        // If the packet is for transferring a chunk of the file
                    } else if (packetType == 1) {

                        int numBytes = fromClient.readInt();
                        byte [] block = new byte[numBytes];
                        fromClient.readFully(block, 0, numBytes);
                        Cipher symmetryCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        symmetryCipher.init(Cipher.DECRYPT_MODE,symmetryKey);

                        if (numBytes > 0){
                            decryptedblock = symmetryCipher.doFinal(block);
                            bufferedFileOutputStream.write(decryptedblock, 0, numBytes);}

                        if (numBytes < 128 && filesreceived < numberoffiles) {
                            filesreceived++;
                            if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                            if (bufferedFileOutputStream != null) fileOutputStream.close();}

                        if (filesreceived == numberoffiles){
                            System.out.println("Closing connection...");
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


                        Cipher rsacipher = Cipher.getInstance("RSA");
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
                    else if (packetType==3){
                        System.out.println("Getting the Symmetry Key");
                        int numBytes = fromClient.readInt();
                        byte[] symmetryKeyFile = new byte[numBytes];
                        fromClient.readFully(symmetryKeyFile, 0, numBytes);

                        // Decrypt the Symmetry Key with the Server's private key
                        Cipher rsaCipher = Cipher.getInstance("RSA");
                        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
                        byte[] decodedKey = rsaCipher.doFinal(symmetryKeyFile);

                        //how to decode from byte back to symmetry key?
//                        symmetryKey = decodedKey.
                    }

                    else if (packetType==11) {
                        numberoffiles = fromClient.readInt();
                    }
                }

            } catch (Exception e) {e.printStackTrace();}

        }
    }

