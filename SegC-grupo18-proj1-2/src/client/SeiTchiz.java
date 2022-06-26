package client;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.Signature;
import java.security.SignatureException;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

//------Cliente------//

public class SeiTchiz {
	
	private static final Scanner sc = new Scanner(System.in); //public static (?)~
	private static String keyStore;
	private static String keyStorePwd;
	private static String trustStore;
	private static String clientID;
	private static PrivateKey privateKey;
	private static PublicKey publicKey;
	
	public static void main(String[] args) {
		try {			
			SeiTchiz client = new SeiTchiz();
			if(args.length != 5) {
				System.out.println("Cliente mal inicializado! (Nº de args inválido)\n Volte a tentar...\n");
			}else {
				trustStore = args[1];
				keyStore = args[2];
				keyStorePwd = args[3];
				clientID = args[4];
				
				//Set Properties
				System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
				System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
				System.setProperty("javax.net.ssl.trustStore", "clientTrustStore"+File.separator+trustStore+".client");
				System.setProperty("javax,net.ssl.trustStorePassword", "123456");
				System.setProperty("javax.net.ssl.keyStore", "clientsKeyStore"+File.separator+clientID+"KeyStore"+File.separator+keyStore);
				System.setProperty("javax.net.ssl.keyStorePassword", keyStorePwd);

				SocketFactory sf = SSLSocketFactory.getDefault();
				SSLSocket s = (SSLSocket) sf.createSocket(args[0], 45678);
				
				System.out.println("Socket criado no client\n");
				ObjectOutputStream outStream = new ObjectOutputStream(s.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(s.getInputStream());
				
				//Envia clientID ao servidor e aguarda resposta.
				long nonce = client.startClient(outStream, inStream, clientID);
				client.setPrivateKey();
				publicKey= getPublicKey(clientID);
				System.out.println("cliente: Inicializado");
				Boolean estaAutenticado = client.autenticacao(outStream, inStream, nonce);
				System.out.println(inStream.readObject());		
				if(estaAutenticado){
					System.out.println("Sessão de: " + clientID);
					menu(outStream, inStream);
				} else {
					System.out.println("Erro ao autenticar!\n");
				}
				//Fecho de canais
				outStream.close(); 	//fecha stream escrita
				inStream.close(); 	//fecha stream leitura
				s.close();		//fecha socket
				
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (SecurityException e) {
			System.out.println("Erro de permissões...");
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}
	

	private Signature signNonceWithPrivate(long nonce) {
		try {
			Signature s = Signature.getInstance("MD5withRSA");
			s.initSign(privateKey);
			ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
			buffer.putLong(nonce);
			byte[] buf = buffer.array();
			s.update(buf);
			return s;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private void setPrivateKey() {
		try {
			FileInputStream keyFile = new FileInputStream("clientsKeyStore"+File.separator+clientID+"KeyStore"+File.separator+keyStore);
			KeyStore kStore = KeyStore.getInstance("JCEKS");
			kStore.load(keyFile, keyStorePwd.toCharArray());
			privateKey = (PrivateKey) kStore.getKey(clientID+"KeyRSA", keyStorePwd.toCharArray());
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}
	}

	private boolean autenticacao(ObjectOutputStream out, ObjectInputStream in, long nonce) {
		try {
			int autent = (int) in.readObject();
			Signature s = signNonceWithPrivate(nonce);
			if(s == null) {
				System.out.println("Erro ao assinar o nonce com a sua private key!");
				return false;
			}else {
				if (autent == 1) {
					System.out.println("Utilizador existente! Aguarde...\n");	
				}else 
					System.out.println("Registando utilizador...\n");			
				out.writeObject(nonce);
				out.writeObject(s.sign());
				return true;			
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	
	public long startClient(ObjectOutputStream out, ObjectInputStream in, String clientID) throws ClassNotFoundException, IOException {
		try {
			out.writeObject(clientID);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return in.readLong();
	}
	
	public static void showMenu() {
	    System.out.println("Menu:");
	    System.out.println("--------------");
	    System.out.println("follow <userID>");
	    System.out.println("unfollow <userID>");
	    System.out.println("viewfollowers");
	    System.out.println("post <photo>");
	    System.out.println("wall <nPhotos>");
	    System.out.println("like <photoID>");
	    System.out.println("newgroup <groupID>");
	    System.out.println("addu <userID> <groupID>");
	    System.out.println("removeu <userID> <groupID>");
	    System.out.println("ginfo <groupID>");
	    System.out.println("msg <groupID> <msg>");
	    System.out.println("collect <groupID>");
	    System.out.println("history <groupID>");
	    System.out.println("--------------");
	}
	
	@SuppressWarnings("unchecked")
	private static void menu(ObjectOutputStream out, ObjectInputStream in) {
		showMenu();
	    try {
	    	String scanner;
		    String option;
		    String result;
		    StringBuilder sb = new StringBuilder();
		    String var1 = null;
		    String var2 = null;
		    String[] tokens = null;
		    Boolean wallCollect;
		    Object o = null;
		    Object o2 = null;
		    do {
		    	System.out.println("Insira o comando: ");
		    	scanner = sc.nextLine();
		 	    tokens = scanner.split(" ");
		 	    option = tokens[0];
		 	    var1 = null;
		 	    var2 = null;
		 	    sb = new StringBuilder();
		 	    if(tokens.length > 1) {
		 	    	var1 = tokens[1];
		 	    	if(tokens.length > 2)
		 	    		var2 = tokens[2];
		 	    }
		        switch (option) {
		        	case "f" :
		        	case "follow" :
		        	case "u" :
		        	case "unfollow" :
		        	case "l" :
		        	case "like" :
		        		out.writeObject(option);
		        		out.writeObject(var1);
		        		if(var2 != null)
		        			out.writeObject(true);
		        		else
		        			out.writeObject(false);
		        		
		        		System.out.println(in.readObject());
		                break;
		                
		        	case "n" :
		        	case "newgroup" :
		        		out.writeObject(option);
		        		out.writeObject(var1);
		
		        		if(var2 != null)
		        			out.writeObject(true);
		        		else
		        			out.writeObject(false);
		        		result = (String) in.readObject();
		        		System.out.println("Result: " + result);
		        		if(!result.equals("Já existe um grupo com esse ID")) {
		        			out.writeObject(cipherKeyWithPub(createGroupKey(), publicKey));
		        			System.out.println(result);
		        		} else {
		        			System.out.println(result);
		        		}
		                break;
		            	
		            case "v" :
		        	case "viewfollowers" :
		        		out.writeObject(option);
		        		if(var1 != null) {
		        			out.writeObject(true);
		        		}else
		        			out.writeObject(false);
		        		
		        		System.out.println(in.readObject());
		                break;
		                
		        	case "p" :
		        	case "post" :
		        		out.writeObject(option);
		        		sendPhoto(var1, out, in);
		        		System.out.println(in.readObject());
		                break;
		                
		        	case "w" :
		        	case "wall" :
		        		out.writeObject(option);
		        		out.writeObject(var1);
		        		if(var2 != null)
		        			out.writeObject(true);
		        		else
		        			out.writeObject(false);
		        		
		        		wallCollect = (Boolean) in.readObject();
		        		if(wallCollect) {
		        			for(int i = 0; i < Integer.parseInt(var1); i++) {
		        				o = in.readObject();
		        				o2 = in.readObject();
		        				if(o != null)
		        					System.out.println(o + "\nNúmero de likes: " + o2);
		        			}
		        				
		        		} else {
		        			System.out.println(in.readObject());
		        		}
		                break;
		   
		        	case "a" :
		        	case "addu" :
		        		out.writeObject(option);
		        		out.writeObject(var1);
		        		out.writeObject(var2);
		        		result = (String) in.readObject();
		  
		        		if(result.equals("Utilizador " + var1 + " adicionado com sucesso ao grupo " + var2)) {		        			
		        			SecretKey newKey = createGroupKey();
		        		    out.writeObject(cipherKeyWithPub(newKey, publicKey));
		        			ArrayList<String> members = (ArrayList<String>) in.readObject();
		        			out.writeObject(listMembersKeys(newKey, members));
		        		}
		        		System.out.println(result);
		                break;  
		                
		        	case "r" :
		        	case "removeu" :
		        		out.writeObject(option);
		        		out.writeObject(var1);
		        		out.writeObject(var2);
		        		result =  (String) in.readObject();
		        		
		        		if(result.equals(var1 + " foi removido com sucesso")) {
		        			SecretKey newKey = createGroupKey();
		        		    out.writeObject(cipherKeyWithPub(newKey, publicKey));
		        		    ArrayList<String> members = (ArrayList<String>) in.readObject();
		        			out.writeObject(listMembersKeys(newKey, members));
		        		}
		        		System.out.println(result);
		                break;     		
		        	
		        	case "g" :
		        	case "ginfo" :
		        		out.writeObject(option);
		        		if(var2 != null) {
		        			out.writeObject(true);
		        			System.out.println(in.readObject());
		        		}
		        		else {
		        			out.writeObject(false);
		        			if(var1 != null) {
			        			out.writeObject(true);
			        			out.writeObject(var1);
			        			System.out.println("Dono do grupo : " + in.readObject());
			        			System.out.println("Membros do grupo: " + in.readObject());
			        		} else {
			        			out.writeObject(false);
			        			System.out.println("Dono dos seguintes grupos: " + in.readObject());
			        			System.out.println("Membro dos seguintes grupos: " + in.readObject());
			        		}
		        		}
		        		
		                break;
		                
		        	case "m" :
		        	case "msg" :
		        		sb.append(var2);
		        		for(int i = 3; i < tokens.length; i++) 
		        			sb.append(" " + tokens[i]);
		        		out.writeObject(option);
		        		out.writeObject(var1);
		        		byte[] groupKey = (byte[]) in.readObject();
		        		out.writeObject(encryptMessage(sb.toString(), decipherKeyWithPriv(groupKey)));
		        		System.out.println(in.readObject());
		                break;   
		        	
		        	case "c" :
		        	case "collect" :
		        	case "h" :
		        	case "history" :
		        		out.writeObject(option);
		        		out.writeObject(var1);
		        		if(var2 != null)
		        			out.writeObject(true);
		        		else
		        			out.writeObject(false);
		        		
		        		wallCollect = (Boolean) in.readObject();
		        		if(wallCollect) {
		        			int aux = (int) in.readObject();
		        			byte[] tempKey;
		        			for(int i = 0; i < aux; i++) {
		        				System.out.print(in.readObject());
		        				tempKey = (byte[]) in.readObject();
		        				if(tempKey != null)
		        					System.out.println(": " + decryptMessage((String) in.readObject(), decipherKeyWithPriv(tempKey)));
		        				else
		        					System.out.println(in.readObject());
		        			}
		        		} else {
		        			System.out.println(in.readObject());
		        		}
		                break;
		            
		        	case "exit":
		        		System.out.println("Terminando sessão...");
		        		break;
		        		
		        	default:
		        		System.out.println("Comando inválido!");
		        		break;
		        }// End of switch statement
		    } while (!option.equals("exit"));
		    
		    //Quando option == exit
		    out.writeObject(option);
	    }catch (Exception e) {
			e.printStackTrace();
		}
	    System.out.println("Obrigado e volte sempre!");
    }

	private static String decryptMessage(String msg, SecretKey key) {
		try {
			Cipher c;
			c = Cipher.getInstance("AES");
			c.init(Cipher.DECRYPT_MODE, key);
			return new String(c.doFinal(Base64.getDecoder().decode(msg)));
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException 
				| InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}			
		
		return null;
	}

	private static HashMap<String, byte[]> listMembersKeys(SecretKey newKey, ArrayList<String> members) {
		HashMap<String, byte[]> result = new HashMap<>();
		PublicKey tempKey;
		byte[] tempCipherKey;
		
		for(int i = 1; i < members.size(); i++) {
			System.out.println(members.get(i).split("\\|")[0]);
			tempKey = getPublicKey(members.get(i).split("\\|")[0]);
			tempCipherKey = cipherKeyWithPub(newKey, tempKey);
			result.put(members.get(i).split("\\|")[0], tempCipherKey);
		}
		
		return result;
	}

	private static SecretKey createGroupKey() {
		KeyGenerator kg;
    	try {
			kg = KeyGenerator.getInstance("AES");
			kg.init(128);
			return kg.generateKey();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
    	return null;

	}

	private static byte[] cipherKeyWithPub(SecretKey key, PublicKey pubKey) {
		Cipher c;
		try {
			c = Cipher.getInstance("RSA");
			c.init(Cipher.WRAP_MODE, pubKey);
			return c.wrap(key);
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
			e.printStackTrace();
		}
		return new byte[0];
	}
	
	private static SecretKey decipherKeyWithPriv(byte[] key) {
		try {
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.UNWRAP_MODE, privateKey);
			return (SecretKey) c.unwrap(key, "AES", Cipher.SECRET_KEY);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private static String encryptMessage(String message, SecretKey key) {
		try {
			Cipher c = Cipher.getInstance("AES");			
			c.init(Cipher.ENCRYPT_MODE, key);
			byte[] messageBytes = message.getBytes("UTF-8");
			return Base64.getEncoder().encodeToString(c.doFinal(messageBytes));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException 
				| UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private static PublicKey getPublicKey(String clientID) {
		FileInputStream fin;
		try {
			fin = new FileInputStream("PubKeys" + File.separator + clientID + "CA.cer");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) cf.generateCertificate(fin);
			return certificate.getPublicKey();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private static void sendPhoto(String var1, ObjectOutputStream out, ObjectInputStream in) throws IOException {
		String photoPath = "photosClient\\" + var1;
		
		try {
			File f = new File(photoPath);
			FileInputStream fin = new FileInputStream(f);
			
			int size = (int) f.length();
			out.writeObject(true);
			out.writeObject(size);
			out.writeObject(var1);
			int aux;
			
			while((aux = fin.read()) > -1) {
				out.write(aux);
			}
			out.flush();

			fin.close();
		
		} catch (FileNotFoundException e) {
			out.writeObject(false);
		} catch (IOException e) {
			e.printStackTrace();
		} 
	}
	
	
}