package server;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.omg.PortableInterceptor.ObjectReferenceFactoryHolder;

import com.sun.swing.internal.plaf.basic.resources.basic_zh_TW;
import com.sun.xml.internal.fastinfoset.algorithm.BooleanEncodingAlgorithm;

import java.util.*;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.sql.Timestamp;

//------Servidor------//

public class SeiTchizServer{
	
	private static Cipher c;
	private static Cipher usersCipher;
	private static PublicKey publicKey;
	private static PrivateKey privateKey;
	private static SecretKey usersKey;
	private int photosCounter;
	private static String serverKeyStore; 
	private static String keystorePwd;
	public static void main(String[] args) {
		SeiTchizServer server = new SeiTchizServer();
		int socketID = Integer.parseInt(args[0]);
		serverKeyStore = args[1];
		keystorePwd = args[2];
		server.startServer(socketID);
	}

	@SuppressWarnings("resource")
	public void startServer (int socketID){
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStore", "serverKeyStore"+File.separator+serverKeyStore);
		System.setProperty("javax.net.ssl.keyStorePassword", keystorePwd);
		
		ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();	
		SSLServerSocket ss = null;
		try {
			ss = (SSLServerSocket) ssf.createServerSocket(socketID);
			//ss.setNeedClientAuth(true);
			File ficheiroContador = new File("users\\photoCounter.txt");
			BufferedReader br = new BufferedReader(new FileReader(ficheiroContador));
	        photosCounter = Integer.parseInt(br.readLine());
	        setPrivateKey();
	        setPublicKey();
	        
	        File usersKeyFile = new File("usersKeyFile");
	        usersCipher = Cipher.getInstance("RSA");
	        if(usersKeyFile.createNewFile()) {
	        	KeyGenerator kg;
	        	kg = KeyGenerator.getInstance("AES");
				kg.init(128);
				usersKey = kg.generateKey();
				usersCipher.init(Cipher.WRAP_MODE, publicKey);
				byte[] wrappedKey = usersCipher.wrap(usersKey);
				FileOutputStream fos = new FileOutputStream(usersKeyFile);
				ObjectOutputStream oos = new ObjectOutputStream(fos);
				oos.writeObject(wrappedKey);
				System.out.println("Ficheiro e chave criados com sucesso");
	        } else {
	        	usersCipher.init(Cipher.UNWRAP_MODE, privateKey);
	        	FileInputStream fis = new FileInputStream(usersKeyFile);
	        	ObjectInputStream ois = new ObjectInputStream(fis);
	        	byte [] unwrappedKey = (byte[]) ois.readObject();
	        	usersKey = (SecretKey) usersCipher.unwrap(unwrappedKey, "AES", Cipher.SECRET_KEY);
	        }
	        
			c = Cipher.getInstance("AES");
	        
	        System.out.println("servidor: inicializado");
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | ClassNotFoundException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}
         
		while(true) {
			try {
				SSLSocket inSoc = (SSLSocket) ss.accept();
				ServerThread newServerThread = new ServerThread(inSoc);
				newServerThread.start();
		    }
		    catch (IOException e) {
		        e.printStackTrace();
		    } catch (SecurityException e) {
		    	System.out.println("Erro de permissões...");
				e.printStackTrace();
		    }
		    
		}
	}
	
	private static void setPrivateKey() {
		try {
			FileInputStream keyFile = new FileInputStream("serverKeyStore"+File.separator+"serverKeys");
			KeyStore kStore = KeyStore.getInstance("JCEKS");
			kStore.load(keyFile, "123456".toCharArray());
			privateKey = (PrivateKey) kStore.getKey("serverkeyRSA","123456".toCharArray());
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
	
	private static void setPublicKey() {
		FileInputStream fin;
		try {
			fin = new FileInputStream("PubKeys"+File.separator+"serverCA.cer");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) cf.generateCertificate(fin);
			publicKey = certificate.getPublicKey();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}
	
	class ServerThread extends Thread {
		private SSLSocket s = null;
		private PublicKey clientPubk;

		ServerThread(SSLSocket inSoc) {
			s = inSoc;
		}
 
		@SuppressWarnings("unchecked")
		public void run(){
			try {
				ObjectOutputStream outStream = new ObjectOutputStream(s.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(s.getInputStream());

				String clientID = null;
			
				try {
					clientID = (String) inStream.readObject();
					System.out.println("ClientID recebido: " + clientID);
					long nonce = new SecureRandom().nextLong();
					System.out.println("Nonce: " + nonce);
					outStream.writeLong(nonce);
					//cria ficheiro users
					File users = new File("src\\users.txt");
					if(users.createNewFile()) {
						System.out.println("Ficheiro users.txt criado com sucesso!");
					}
						
					
					
					//AUTENTICACAO
					int autent = verificaUser(clientID);
					outStream.writeObject(autent);
					long nonceReceived = (long) inStream.readObject();
					byte[] signature = (byte[]) inStream.readObject();
					setClientPubk(clientID);
					
					if(nonce == nonceReceived && !verifySignature(nonceReceived, signature)) {
						System.out.println("Assinatura Falsa!!");
						outStream.writeBytes("Autenticação nao foi bem sucedida!\n");
					}else {
						System.out.println("Utilizador válido!\n");
						
						if(autent == 0) { 
							registaUser(clientID);
							outStream.writeObject("Autenticação e registo bem sucedidos de " + clientID + " !\n");
						}else
							outStream.writeObject("Autenticação bem sucedida!\n");
						
						String option = null;
						String userID = null;
						String result = null;
						Boolean info = null;
						String var = null;
						List<List<String>> collectAndHistoryResult = new ArrayList<>();
						List<String> result2 = new ArrayList<>();
						String[] result3;
						do {
							option = (String) inStream.readObject();
		
							if(option.equals("f") || option.equals("follow")) {
								userID = (String) inStream.readObject();
								if((Boolean) inStream.readObject() || userID == null) {
									result = "Comando follow mal efetuado!";
								}else
									result = follow(userID, clientID);
								
								outStream.writeObject(result);
							}
							
							if(option.equals("u") || option.equals("unfollow")) {
								userID = (String) inStream.readObject();
								if((Boolean) inStream.readObject() || userID == null) {
									result = "Comando unfollow mal efetuado!";
								}else 
									result = unfollow(userID, clientID);
								outStream.writeObject(result);
							}
							
							if(option.equals("v") || option.equals("viewfollowers")) {
								if((Boolean) inStream.readObject())
									result = "Comando viewfollowers mal efetuado!";
								else
									result = viewfollowers(clientID);
								outStream.writeObject(result);
							}

							if(option.equals("p") || option.equals("post")) {
								result = post(outStream, inStream, clientID);
								outStream.writeObject(result);
							}
							
							if(option.equals("l") || option.equals("like")) {
								var = (String) inStream.readObject();
								if((Boolean) inStream.readObject() || var == null)
									result = "Comando like mal efetuado!";
								else 
									result = like(var, clientID);
								outStream.writeObject(result);
							}
							
							if(option.equals("w") || option.equals("wall")) {
								var = (String) inStream.readObject();
								if((Boolean) inStream.readObject() || var == null) {
									outStream.writeObject(false);
									outStream.writeObject("Comando wall mal efetuado!");
								}else {
									try {
										result3 = wall(Integer.parseInt(var), clientID);
										
										if(result3 != null) {
											outStream.writeObject(true);
											for(int i = 0; i < result3.length; i++) {
												outStream.writeObject(result3[i]);
											}
										} else {
											outStream.writeObject(false);
											outStream.writeObject("Erro no Wall");
										}
										
									}catch(NumberFormatException e) {
										outStream.writeObject(false);
										outStream.writeObject("Comando wall mal efetuado!");
									}
								}
							}
							
							if(option.equals("n") || option.equals("newgroup")) {
								userID = (String) inStream.readObject();
								if((Boolean) inStream.readObject() || userID == null)
									result = "Comando newgroup mal efetuado!";
								else 
									result = newgroup(clientID, userID);
								outStream.writeObject(result);
								
								if(!result.equals("Já existe um grupo com esse ID")) {
									byte[] key = (byte[]) inStream.readObject();
									setGroupKey(key, userID, clientID);
								}
							}
							
							if(option.equals("a") || option.equals("addu")) {
								userID = (String) inStream.readObject(); //userID
								var = (String) inStream.readObject(); //groupID
								result = addu(userID, var, clientID);
								System.out.println("Result enviado:" + result);
								outStream.writeObject(result);
								
								
								if(result.equals("Utilizador " + userID + " adicionado com sucesso ao grupo " + var)) {
									byte[] key = (byte[]) inStream.readObject();
									if(key.length == 0) 
										System.out.println("Erro ao cifrar a nova chave de grupo com a chave pública do owner!\n");
									
									setGroupKey(key, var, clientID);
									ArrayList<String> members = getGroupMembers(var);
									if(members.isEmpty())
										System.out.println("Erro no getGroupMembers!\n");
									outStream.writeObject(members);
									setListMembersKeys((HashMap<String, byte[]>) inStream.readObject(), var);
								}								
							}
							
							if(option.equals("r") || option.equals("removeu")) {
								userID = (String) inStream.readObject(); //userID
								var = (String) inStream.readObject(); //groupID
								result = removeu(userID, var, clientID);
								outStream.writeObject(result);
								
								if(result.equals(userID + " foi removido com sucesso")) {
									byte[] key = (byte[]) inStream.readObject();
									if(key.length == 0) 
										System.out.println("Erro ao cifrar a nova chave de grupo com a chave pública do owner!\n");
									
									setGroupKey(key, var, clientID);
									ArrayList<String> members = getGroupMembers(var);
									if(members.isEmpty())
										System.out.println("Erro no getGroupMembers!\n");
									outStream.writeObject(members);
									setListMembersKeys((HashMap<String, byte[]>) inStream.readObject(), var);
								}
							}
							
							if(option.equals("g") || option.equals("ginfo")) {
								if((Boolean) inStream.readObject())
									outStream.writeObject("Comando ginfo mal efetuado!");
								else {
									info = (Boolean) inStream.readObject(); // true se tem id do grupo
									if(info) {
										var = (String) inStream.readObject(); //groupID
										result2 = groupInfo(var, clientID); 
									}else {
										result2 = groupInfo(clientID);
									}
									String owner = result2.get(0);
									String member = result2.get(1);
									outStream.writeObject(owner);
									outStream.writeObject(member);
								}
							}
							
							if(option.equals("m") || option.equals("msg")) {
								userID = (String) inStream.readObject(); //groupID
								outStream.writeObject(getGroupKey(userID, clientID));
								var = (String) inStream.readObject(); //msg			
								result = msg(userID, var, clientID);
								outStream.writeObject(result);
							}
							
							if(option.equals("c") || option.equals("collect")) {
								userID = (String) inStream.readObject();
								if((Boolean) inStream.readObject() || userID == null) {
									outStream.writeObject(false);
									outStream.writeObject("Comando collect mal efetuado!");
								}else {
									outStream.writeObject(true);
									collectAndHistoryResult = collect(userID, clientID);
										
									if(collectAndHistoryResult != null) {
										//Envia informação da mensagem ao cliente
										sendMessageInfo(collectAndHistoryResult, outStream, clientID, userID);		
									} else {
										outStream.writeObject(false);
										outStream.writeObject("Erro no Collect");
									}
								}
							
							}
							
							if(option.equals("h") || option.equals("history")) {
								userID = (String) inStream.readObject(); //groupID
								if((Boolean) inStream.readObject() || userID == null) {
									outStream.writeObject(false);
									outStream.writeObject("Comando history mal efetuado!");
								}else {
									outStream.writeObject(true);
									collectAndHistoryResult = history(clientID, userID);
										
									if(collectAndHistoryResult != null) {
										//Envia informação da mensagem ao cliente
										sendMessageInfo(collectAndHistoryResult, outStream, clientID, userID);
									} else {
										outStream.writeObject(false);
										outStream.writeObject("Erro no History");
									}
								}
							}
							
						}while(!option.equals("exit"));	
					}
				}catch (Exception e) {
					e.printStackTrace();
				}
 			
				outStream.close();
				inStream.close();
				s.close();

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		private void sendMessageInfo(List<List<String>> collectAndHistoryResult, ObjectOutputStream outStream, String clientID, String groupID) {
			try {
				outStream.writeObject(collectAndHistoryResult.size());
				
				for(int i = 0; i < collectAndHistoryResult.size(); i++) {
					//System.out.println(collectAndHistoryResult.get(i).get(0));
					outStream.writeObject(collectAndHistoryResult.get(i).get(0)); //Quem enviou a mensagem
					//chave(cifrada com a chabe publica do clientID que executou o collect) para decifrar a mensagem.
					if(collectAndHistoryResult.get(i).get(1).equals(""))
						outStream.writeObject(null);
					else {
						System.out.println(collectAndHistoryResult.get(i).get(1));
						outStream.writeObject(getKeys(clientID, groupID).get(Integer.parseInt(collectAndHistoryResult.get(i).get(1))));
					}
						
					outStream.writeObject(collectAndHistoryResult.get(i).get(2)); //mensagem cifrada
				}
				
			} catch (IOException e) {
				e.printStackTrace();
			}
			
		}

		@SuppressWarnings("unchecked")
		private byte[] getGroupKey(String groupID, String clientID) {
			File clientGroupKeys = new File("groups" + File.separator + groupID + File.separator + clientID + "-GroupKeys");
			try {
				
				FileInputStream fis = new FileInputStream(clientGroupKeys);
				ObjectInputStream ois = new ObjectInputStream(fis);
				HashMap<Integer, byte[]> keys = (HashMap<Integer, byte[]>) ois.readObject();
				fis.close();
				ois.close();
				return (byte[]) keys.values().toArray()[keys.size()-1];
			} catch (IOException | ClassNotFoundException e) {
				e.printStackTrace();
			}
			return new byte[0];
 		}

		@SuppressWarnings("unchecked")
		private void setListMembersKeys(HashMap<String, byte[]> hashMembers, String groupID) {
			try {
				String tempUser;
				File tempFile;
				HashMap<Integer, byte[]> tempKeys = new HashMap<>();
				for(Map.Entry<String, byte[]> entry : hashMembers.entrySet()) {
					tempUser = entry.getKey();
					tempFile = new File("groups" + File.separator + groupID + File.separator + tempUser + "-GroupKeys");
					if(tempFile.length() != 0) {
						System.out.println("ola fofo\n");
						FileInputStream fis = new FileInputStream(tempFile);
						ObjectInputStream ois = new ObjectInputStream(fis);
						tempKeys = (HashMap<Integer, byte[]>) ois.readObject();
						fis.close();
						ois.close();
					}
					
					File identificador = new File("groups"+ File.separator + groupID + File.separator + "identificador.txt");
					BufferedReader br = new BufferedReader(new FileReader(identificador));
					tempKeys.put(Integer.parseInt(br.readLine()), entry.getValue());
					
					FileOutputStream fosTemp = new FileOutputStream(tempFile);
					ObjectOutputStream oosTemp = new ObjectOutputStream(fosTemp);
					oosTemp.writeObject(tempKeys);
					
					br.close();
					fosTemp.close();
					oosTemp.close();
				}
						
			} catch (IOException | ClassNotFoundException e) {
				e.printStackTrace();
			}
		}

		private ArrayList<String> getGroupMembers(String var) {
			ArrayList<String> result = new ArrayList<>();
			try {
				File members = new File("groups" + File.separator + var + File.separator + "members.txt");
				BufferedReader br = new BufferedReader(new FileReader(members));
				String line;
				while((line = br.readLine()) != null) {
					result.add(line.substring(0, line.length() - 1));
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
			return result;
		}

		private boolean verifySignature(long nonce, byte[] signature) {
			Signature sign;
			try {
				sign = Signature.getInstance("MD5withRSA");
				sign.initVerify(clientPubk);
				ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
				buffer.putLong(nonce);
				byte[] buf = buffer.array();
				sign.update(buf);
				if(sign.verify(signature))
					return true;
				else
					return false;
				
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			}
			return false;
		}
		
		private void setClientPubk(String clientID) {
			FileInputStream fin;
			try {
				fin = new FileInputStream("PubKeys"+File.separator+clientID+"CA.cer");
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				X509Certificate certificate = (X509Certificate) cf.generateCertificate(fin);
				clientPubk = certificate.getPublicKey();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			}
			
		}
		
		private String isMember(List<String> members, String userID) {
			String result = "";
			
			for(int i = 0; i < members.size(); i++) 
				if(members.get(i).split("\\|")[0].equals(userID)) {
					result = members.get(i);
					break;
				}
			
			return result;
		}	
		
		private List<List<String>> history(String clientID, String groupID) {
			List<List<String>> result = new ArrayList<>();
			if(Files.isDirectory(Paths.get("groups\\" + groupID))) { //VERIFICAR SE O GRUPO EXISTE
				File group = new File("groups\\" + groupID + "\\members.txt");
				List<String> members = fileToList(group);
				String isMember = isMember(members, clientID);
				
				if(!isMember.equals("")) { //VERIFICAR SE ESTÁ NO GRUPO
					try {
						File messages = new File("groups\\" + groupID + "\\messages.txt");
						BufferedReader br = new BufferedReader(new FileReader(messages));
						String currentLine;
						String[] tokens, tokens1;
						Boolean jaLeu;
						//File history = new File("users\\" + clientID + "\\history_" + groupID + ".txt");
						
						while((currentLine = br.readLine()) != null) {
							jaLeu = false;
							tokens = currentLine.split(":");
							tokens1 = tokens[tokens.length - 1].split(";");
							for(int i = 0; i < tokens1.length; i++) {
								if(tokens1[i].equals(clientID)) {
									jaLeu = true;
									break;
								}
							}
							
							if(jaLeu) {
								List<String> temp = new ArrayList<>();
								temp.add(tokens[0]);
								temp.add(tokens[1]);
								temp.add(tokens[2]);
								result.add(temp);
							}
						}
						
						if(result.isEmpty()) {
							List<String> temp = new ArrayList<>();
							temp.add("");
							temp.add("");
							temp.add("Não tem mensagens por ler!");
							result.add(temp);
						}
							
						
						//Files.write(history.toPath(), result);
						br.close();
						return result;
						
					}catch(IOException e) {
						e.printStackTrace();
					}	
				}else {
					List<String> temp = new ArrayList<>();
					temp.add("");
					temp.add("");
					temp.add("Não pertence ao grupo " + groupID);
					result.add(temp);
				}
			}else {
				List<String> temp = new ArrayList<>();
				temp.add("");
				temp.add("");
				temp.add("O grupo " + groupID + "não existe!");
				result.add(temp);
			}
			return result;
		}

		private ArrayList<String> groupInfo(String clientID) {
			ArrayList<String> result = new ArrayList<String>();
			if(!Files.exists(Paths.get("users\\" + clientID + "\\owner.txt"))) { //verificar se é dono de algum grupo
				result.add("Não é dono de nenhum grupo!");
				if(!Files.exists(Paths.get("users\\" + clientID + "\\member.txt"))) { //verificar se é membro de algum grupo
					result.add("Não é membro de nenhum grupo!");
				}else {
					File member = new File("users\\" + clientID + "\\member.txt");
					List<String> list = fileToList(member);
					StringBuilder sb = new StringBuilder();
					for(int i = 0; i < list.size(); i++) {
						sb.append(list.get(i).substring(0, list.get(i).length() - 1) + " | ");
					}
					result.add(sb.toString());
				}
			}else {
				File owner = new File("users\\" + clientID + "\\owner.txt");
				List<String> list = fileToList(owner);
				StringBuilder sb = new StringBuilder();
				for(int i = 0; i < list.size(); i++) {
					sb.append(list.get(i).substring(0, list.get(i).length() - 1) + " | ");
				}
				result.add(sb.toString());
				if(!Files.exists(Paths.get("users\\" + clientID + "\\member.txt"))) { //verificar se é membro de algum grupo do qual não é dono
					result.add("É membro dos grupos que é dono!");
				}else {
					File member = new File("users\\" + clientID + "\\member.txt");
					List<String> list2 = fileToList(member);
					StringBuilder sb2 = new StringBuilder();
					for(int i = 0; i < list2.size(); i++) {
						sb2.append(list2.get(i).substring(0, list2.get(i).length() - 1) + " | ");
					}
					result.add(sb2.toString());
				}
			}
			return result;
		}

		private ArrayList<String> groupInfo(String groupID, String clientID) {
			ArrayList<String> result = new ArrayList<>();
			if(!Files.isDirectory(Paths.get("groups\\" + groupID))) { //verificar se grupo existe
				result.add(groupID + " não existe!");
				result.add(groupID + " não existe!");
			}else {
				File members = new File("groups\\" + groupID + "\\members.txt");
				List<String> list = fileToList(members);
				String isMember = isMember(list, clientID);
				if(isMember.equals("")) {
					result.add("Não tem acesso a essa informação visto que não pertence ao grupo " + groupID);
					result.add("Não tem acesso a essa informação visto que não pertence ao grupo " + groupID);
				} else {
					StringBuilder sb = new StringBuilder();
					for(int i = 1; i < list.size(); i++) 
						sb.append(list.get(i).split("\\|")[0] + " | ");
					
					result.add(list.get(0).split("\\|")[0]);
					result.add(sb.toString());
				}	
			}
			return result;
		}

		private String removeu(String userID, String groupID, String clientID) throws IOException {
			if(userID == null || groupID == null)
				return "Comando removeu mal efetuado!";
			
			if(Files.isDirectory(Paths.get("groups\\" + groupID))) {
				File members = new File("groups\\" + groupID + "\\members.txt");
				List<String> list = fileToList(members);
				String toRemove = isMember(list, userID);
				
				if(toRemove.equals("")) 
					return userID + " não pertence ao grupo " + groupID;
				
				if(list.get(0).split("\\|")[0].equals(clientID)) {
					File historyFile = new File("users\\" + userID + "\\history_" + groupID + ".txt");
					Boolean deleteH = historyFile.delete();
					File membersList = new File("users\\" + userID + "\\member.txt");
					int result = removeString(members, toRemove);
					int resultTwo = removeString(membersList, groupID + ";");
					
					if((result + resultTwo) == 2 && deleteH)
						return userID + " foi removido com sucesso";
					else
						return "Erro ao remover " + userID + " do grupo " + groupID;		
				} else
					return "Só o dono pode remover utilizadores ao grupo";
			}
			return groupID + " não existe";
		}
	
		private String addu(String userID, String groupID, String clientID) throws IOException {
			if(userID == null || groupID == null)
				return "Comando addu mal efetuado!";
			
			if(Files.isDirectory(Paths.get("groups\\" + groupID))) {
				File members = new File("groups\\" + groupID + "\\members.txt");
				List<String> list = fileToList(members);

				if(list.get(0).split("\\|")[0].equals(clientID)) {
					String isMember = isMember(list, userID);
					if(!isMember.equals(""))
						return userID + " já pertence ao grupo!";
					
					if(!Files.exists(Paths.get("users\\" + userID + "\\history_" + groupID + ".txt"))) {
						File history = new File("users\\" + userID + "\\history_" + groupID + ".txt");
						Boolean historyB = history.createNewFile();
						if(!historyB) {
							System.out.println("Erro ao criar history_" + groupID + ".txt do user" + userID);
							return "Erro ao adicionar o histórico";
						}
					}
					
					if(!Files.exists(Paths.get("users\\" + userID + "\\member.txt"))) {
						File member = new File("users\\" + userID + "\\member.txt");
						Boolean memberB = member.createNewFile();
						if(!memberB) {
							return "Erro ao adicionar o grupo ao utilizador";
						}
						else { 
							BufferedWriter bw2 = new BufferedWriter(new FileWriter(member, true));
							bw2.write(groupID + ";");
							bw2.close();
							System.out.println("member.txt registado com sucesso no perfil do " + userID +"!");
						}
						
						
					}else {
						File member = new File("users\\" + userID + "\\member.txt");
						BufferedWriter bw3 = new BufferedWriter(new FileWriter(member, true));
						bw3.append(groupID + ";");
						bw3.close();
						System.out.println(groupID + "adicionado com sucesso ao member.txt no perfil do " + userID +"!");
					}
					
					//Cria userID-GroupKeys
					File userGroupKeys = new File("groups" + File.separator + groupID + File.separator + userID + "-GroupKeys");
					if(userGroupKeys.createNewFile())
						System.out.println(userID + "-GroupKeys criado com sucesso!");
					else
						System.out.println("Erro ao criar " + userID + "-GroupKeys;\n");
					
					BufferedWriter bw = new BufferedWriter(new FileWriter(members, true));
					bw.append(userID + "|" + userID + "-GroupKeys;\n" );
					bw.close();
					return "Utilizador " + userID + " adicionado com sucesso ao grupo " + groupID;
				} else {
					return "Só o dono pode adicionar utilizadores ao grupo";
				}
			}else {
				return groupID + " não existe";
			}
		}

		@SuppressWarnings("resource")
		private String newgroup(String clientID, String groupID) throws IOException {
			if(!Files.isDirectory(Paths.get("groups\\" + groupID))) {
				Boolean groupFolderCreate = new File("groups\\" + groupID).mkdir();
				File members = new File("groups\\" + groupID + "\\members.txt");
				Boolean createMembers = members.createNewFile();
				File messages = new File("groups\\" + groupID + "\\messages.txt");
				Boolean createMessages = messages.createNewFile();
				File ownerGroupKeys = new File("groups\\" + groupID + File.separator + clientID + "-GroupKeys");
				Boolean ownerGKB = ownerGroupKeys.createNewFile();
				File identificador = new File("groups\\" + groupID + "\\identificador.txt");
				Boolean createId = identificador.createNewFile();
				
				if(groupFolderCreate && createMembers && createMessages && createId && ownerGKB) {
					BufferedWriter bw = new BufferedWriter(new FileWriter(members, true));
					BufferedWriter bwId = new BufferedWriter(new FileWriter(identificador, true));
					Timestamp t = new Timestamp(System.currentTimeMillis());
					bw.write(clientID + "|" + t + "|" + clientID + "-GroupKeys;\n");
					bwId.write("-1");
					bw.close();
					bwId.close();
					
					if(!Files.exists(Paths.get("users\\" + clientID + "\\owner.txt"))) {
						File owner = new File("users\\" + clientID + "\\owner.txt");
						File history = new File("users\\" + clientID + "\\history_" + groupID + ".txt");
						Boolean historyB = history.createNewFile();
						Boolean ownerB = owner.createNewFile();
						if(!ownerB || !historyB) 
							System.out.println("Erro ao adicionar o grupo ao utilizador");
						else { 
							BufferedWriter bw2 = new BufferedWriter(new FileWriter(owner, true));
							bw2.write(groupID + ";" + "\n");
							bw2.close();
						}
					}else {
						File owner = new File("users\\" + clientID + "\\owner.txt");
						BufferedWriter bw3 = new BufferedWriter(new FileWriter(owner, true));
						bw3.append(groupID + ";" + "\n");
						bw3.close();
					}
					
					return "Grupo " + groupID + " criado com sucesso";
				}
			}
			return "Já existe um grupo com esse ID";
		}

		@SuppressWarnings("resource")
		private String follow(String userToFollow, String clientID) throws IOException {
			if(Files.isDirectory(Paths.get("users\\" + userToFollow))) {
				File followers = new File("users\\" + userToFollow + "\\followers.txt");
				File following = new File("users\\" + clientID + "\\following.txt");
				BufferedWriter bw = new BufferedWriter(new FileWriter(followers, true)); //followers 
				BufferedWriter bw2 = new BufferedWriter(new FileWriter(following, true)); //following
				List<String> list = fileToList(following);
				
				if(!list.contains(userToFollow + ";")) {
					bw.append(clientID + ";");
					bw2.append(userToFollow + ";");
					bw.close();
					bw2.close();
					return "Seguiu " + userToFollow + " com sucesso!";
				}else {
					bw.close();
					bw2.close();
					return "Já seguia " + userToFollow;
				}
			}else {
				return "userID nao existe";
			}
		}
		
		@SuppressWarnings("resource")
		private String unfollow(String userToUnfollow, String clientID) throws IOException {
			if(Files.isDirectory(Paths.get("users\\" + userToUnfollow))) {
				
				File followers = new File("users\\" + userToUnfollow + "\\followers.txt");
				File following = new File("users\\" + clientID + "\\following.txt");	
				int removed = removeString(followers, clientID + ";") + removeString(following, userToUnfollow + ";");
				System.out.println(removed + "\n");

				
				if(removed == 2) {
					return "Unfollow com sucesso!";
				}
				
				if(removed < 2 && removed >= 0) {
					return "Já não seguia o user " + userToUnfollow;
				}
			}
			return "userID nao existe";
		}
		
		private int removeString(File file, String toRemove) {
			try {
				List<String> list = fileToList(file);
				if(list.contains(toRemove)){
					for(int i = 0; i < list.size(); i++) {
						if(list.get(i).equals(toRemove)) {
							list.remove(list.get(i));
							new PrintWriter(file.getPath()).close();
							BufferedWriter bw = new BufferedWriter(new FileWriter(file, true));
							for(int j = 0; j < list.size(); j++)
								bw.append(list.get(j) + "\n");
							bw.close();
							return 1;
						}
					}
				}
				return 0;
			}catch(IOException e) {
				e.printStackTrace();
			}
			return -1;
		}
		
		private List<String> fileToList(File file){
			List<String> result = new ArrayList<>();
			try {
				BufferedReader br = new BufferedReader(new FileReader(file));
				String currentLine;
				
				while((currentLine = br.readLine()) != null) {
					String[] tokens = currentLine.split(";");
					for(int i = 0; i < tokens.length; i++) {
						result.add(tokens[i] + ";");
					}
				}
				
				br.close();
				return result;
				
			}catch (IOException e) {
				return result;
			}
		}
		
		@SuppressWarnings("resource")
		private String viewfollowers (String clientID) throws IOException {
			File followers = new File("users\\" + clientID + "\\followers.txt");
			List<String> lines = fileToList(followers);
			if(lines.size() > 0) {
				StringBuilder sb = new StringBuilder();
				for(int i = 0; i < lines.size(); i++) {
					sb.append(lines.get(i).substring(0, lines.get(i).length() - 1) + "\n");
				}
				return sb.toString();
			}
			return "Não tem seguidores";
		}
		
		private String post(ObjectOutputStream outStream, ObjectInputStream inStream, String clientID){
			
				boolean ficheiroExiste;
				try {
					ficheiroExiste = (boolean) inStream.readObject();
					if(ficheiroExiste) {
						int size = (int) inStream.readObject();
						String var = (String) inStream.readObject();
						String tokens[] = var.split("\\.");
						String photoName = clientID + "_" + photosCounter;
						FileOutputStream fos = new FileOutputStream("users" +File.separator+ clientID +File.separator+"photos" +File.separator+ photoName +"."+tokens[1]);
						FileOutputStream fosHash = new FileOutputStream("users" +File.separator+ clientID +File.separator+"photos" +File.separator+ photoName +"_hash");
						MessageDigest md = MessageDigest.getInstance("SHA");
						ObjectOutputStream oos = new ObjectOutputStream(fosHash);
						
						//guarda imagem original
						for(int j = 0; j < size; j++) {
							fos.write(inStream.read());
						}
						
						//síntese segura
						File foto = new File("users" +File.separator+ clientID +File.separator+"photos" +File.separator+ photoName+"."+tokens[1]);
						byte[] buf = Files.readAllBytes(foto.toPath());
						byte[] hash = md.digest(buf);
						oos.writeObject(hash);
						
						fos.close();
						oos.close();
						
						File likes = new File("users\\" + clientID + "\\photos\\" + photoName + ".txt");
						Boolean likesB = likes.createNewFile();
						if(!likesB) {
							System.out.println("Erro ao criar txt da foto.");
						}
						
						File ficheiroContador = new File("users\\photoCounter.txt");
						BufferedWriter bw = new BufferedWriter(new FileWriter(ficheiroContador));
						photosCounter++;
						bw.append("" + photosCounter);
						bw.close();
						return "Publicada com sucesso!";
					}else {
						return "Foto não encontrada";
					}
				} catch (ClassNotFoundException | IOException e) {
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				return "Erro ao publicar a foto";
		}
		
		private String like(String nome, String clientID) {
			try {
				String[] tokens = nome.split("_");
				if(!Files.exists(Paths.get("users\\" + tokens[0] + "\\photos\\" + nome + ".txt"))) {
					return "Foto não encontrada!";
				}else {
					File txt = new File("users\\" + tokens[0] + "\\photos\\" + nome + ".txt");
					List<String> list = fileToList(txt);
					for(int i = 0; i < list.size(); i++) {
						System.out.println(list.get(i));
					}
					
					if(list.contains(clientID + ";")) {
						return "Já gostou desta foto!";
					} else {
						BufferedWriter bw = new BufferedWriter(new FileWriter(txt, true));
						bw.append(clientID + ";");
						bw.close();
						return "Like com sucesso!";
					}	
				}
			} catch (IOException e) {
				e.printStackTrace();
			} 
			return "Erro no Like!";
		}

		private String[] wall(int numberOfPhotos, String clientID) throws ClassNotFoundException, IOException{
			String[] result = new String[numberOfPhotos*2];
			try {
				File following = 
						new File("users\\" + clientID + "\\following.txt");
				
				List<String> followingUsers = fileToList(following);
				HashMap<String, Integer> imagesMap = new HashMap<>();
				String currentUser;
				int index;
				int aux;
				int temp = 0;
				String fileName;
				
				
				for(int i = 0; i < followingUsers.size(); i++) {
					currentUser = followingUsers.get(i).substring(0, followingUsers.get(i).length() - 1);
					String[] tokens;
					String[] tokensHash;
					String[] tokensAux;
					File folder = new File("users\\" + currentUser + "\\photos");
					if(folder.isDirectory()) {
						File[] ficheirosFotos = folder.listFiles();
						for(int j = 0; j < ficheirosFotos.length; j++) {
							fileName = ficheirosFotos[j].getName();
							//index = fileName.lastIndexOf('.');
							tokensAux = fileName.split("\\.");
							tokensHash = tokensAux[0].split("_");
							if(!(tokensHash.length > 2) && !tokensAux[1].equals("txt")) {
								aux = fileName.lastIndexOf('_');
								tokens = fileName.substring(aux+1).split("\\.");
								imagesMap.put(fileName, Integer.parseInt(tokens[0]));
							}
						}
					}
				}
				
				imagesMap = sortHashByValue(imagesMap);
				Object[] keys = imagesMap.keySet().toArray();
				String photoName;
				String[] user;
				String[] auxiliar;
				File txt;
				
				while(temp < numberOfPhotos*2 && temp < imagesMap.size()*2) {
					photoName = (String) keys[temp/2];					
					user = photoName.split("_");
					auxiliar = photoName.split("\\.");
					txt = new File("users\\" + user[0] + "\\photos\\" + auxiliar[0] + ".txt");
					
					//leitura e verificação da síntese
					File foto = new File("users\\" + user[0] + "\\photos\\" + photoName);
					FileInputStream fis = new FileInputStream("users\\" + user[0] + "\\photos\\" + photoName);
					FileInputStream fisHash = new FileInputStream("users\\" + user[0] + "\\photos\\" + auxiliar[0] + "_hash");
					ObjectInputStream ois = new ObjectInputStream(fisHash);
					byte[] photoByte = Files.readAllBytes(foto.toPath());
				
					//ler hash
					byte[] hash = (byte[]) ois.readObject();
					MessageDigest md = MessageDigest.getInstance("SHA");
					if(MessageDigest.isEqual(md.digest(photoByte), hash)) {
						result[temp] = auxiliar[0];
					}else {
						result[temp] = "Foto corrompida!";
					}
				
					result[temp+1] = String.valueOf(fileToList(txt).size());
					temp+=2; 
					fis.close();
					fisHash.close();
					ois.close();
				}
				return result;
				
			}catch(Exception e) {
				e.printStackTrace();
			}
			
			return result;
		}
		
		private HashMap<String, Integer> sortHashByValue(HashMap<String, Integer> map){
			List<Map.Entry<String, Integer>> list = new LinkedList<Map.Entry<String, Integer>>(map.entrySet());
			
			Collections.sort(list, new Comparator<Map.Entry<String, Integer> >() { 
	            public int compare(Map.Entry<String, Integer> o1,  
	                               Map.Entry<String, Integer> o2) 
	            { 
	                return (o2.getValue()).compareTo(o1.getValue()); 
	            } 
	        }); 
			
			HashMap<String, Integer> temp = new LinkedHashMap<String, Integer>();
			for(Map.Entry<String, Integer> aa : list) {
				temp.put(aa.getKey(), aa.getValue());
			}
			
			return temp;
		}
		 
		private String msg(String groupID, String msg, String clientID) {
			try {
				if(Files.isDirectory(Paths.get("groups\\" + groupID))) {
					File group = new File("groups\\" + groupID + "\\members.txt");
					List<String> members = fileToList(group);
					String isMember = isMember(members, clientID);
					
					if(!isMember.equals("")) {
						File identificador = new File("groups" + File.separator + groupID + File.separator + "identificador.txt");
						BufferedReader bwIdentificador = new BufferedReader(new FileReader(identificador));
						int id = Integer.parseInt(bwIdentificador.readLine());
						File messages = new File("groups\\" + groupID + "\\messages.txt");
						BufferedWriter bw = new BufferedWriter(new FileWriter(messages, true));
						bw.append(clientID + ":"+ id + ":" + msg + ":" + clientID + ";" + "\n");
						bwIdentificador.close();
						bw.close();
						
						return "Mensagem enviada com sucesso!";
					}
					return "Não pode enviar mensagens para " + groupID + " visto que não pertence a este!";
				}
				return "O grupo indicado (" + groupID + ") não existe!";
			}catch (IOException e) {
				e.printStackTrace();
			}
			return "Erro ao enviar a mensagem!";
		}
			
		private List<List<String>> collect(String groupID, String clientID){
			List<List<String>> result = new ArrayList<>();
			if(Files.isDirectory(Paths.get("groups\\" + groupID))) {
				File group = new File("groups\\" + groupID + "\\members.txt");
				List<String> members = fileToList(group);
				String isMember = isMember(members, clientID);
										
				if(!isMember.equals("")) {
					try {
						File messages = new File("groups\\" + groupID + "\\messages.txt");
						BufferedReader br = new BufferedReader(new FileReader(messages));
						String currentLine;
						String[] tokens;
						String[] tokens1;
						Boolean jaViu;
						List<String> newMessages = new ArrayList<>();
						
						while((currentLine = br.readLine()) != null) {
							System.out.println("Current Line: " + currentLine);
							jaViu = false;
							tokens = currentLine.split(":");
							tokens1 = tokens[tokens.length - 1].split(";");
							for(int i = 0; i < tokens1.length; i++) {
								if(tokens1[i].equals(clientID)) {
									jaViu = true;
									break;
								}
							}
							
							HashMap<Integer, byte[]> clientKeys = getKeys(clientID, groupID);
							if(!jaViu && clientKeys.containsKey(Integer.parseInt(tokens[1]))) { 
								List<String> temp = new ArrayList<>();
								temp.add(tokens[0]);
								temp.add(tokens[1]);
								temp.add(tokens[2]);
								result.add(temp);								
								currentLine = currentLine + clientID + ";";
							}
							newMessages.add(currentLine);
						}
						
						if(result.isEmpty()) {
							List<String> temp = new ArrayList<>();
							temp.add("");
							temp.add("");
							temp.add("Não tem mensagens por ler!");
							result.add(temp);
						}
							
						
						Files.write(messages.toPath(), newMessages);
						br.close();
						return result;
						
					}catch(IOException e) {
						e.printStackTrace();
					}	
				}else {
					List<String> temp = new ArrayList<>();
					temp.add("");
					temp.add("");
					temp.add("Não pertence ao grupo " + groupID);
					result.add(temp);
				}
					
			}else {
				List<String> temp = new ArrayList<>();
				temp.add("");
				temp.add("");
				temp.add("O grupo " + groupID + "não existe!");
				result.add(temp);
			}
			return result;
		}
			
		@SuppressWarnings("unchecked")
		private  HashMap<Integer, byte[]> getKeys(String clientID, String groupID) {
			try {
				File clientGK = new File("groups" + File.separator + groupID + File.separator + clientID + "-GroupKeys");
				FileInputStream fis = new FileInputStream(clientGK);
				ObjectInputStream ois = new ObjectInputStream(fis);
				HashMap<Integer, byte[]> keys = (HashMap<Integer, byte[]>) ois.readObject();
				fis.close();
				ois.close();
				return keys;
				
			} catch (ClassNotFoundException | IOException e) {
				e.printStackTrace();
			}
			return new HashMap<Integer, byte[]>();
		}
		

		@SuppressWarnings("resource")
		private int verificaUser(String clientID) throws IOException {
			File users = new File("src\\users.txt");
			if(users.length() == 0)
				return 0;
			
			//Decifrar
			try {
				c.init(Cipher.DECRYPT_MODE, usersKey);
				BufferedReader br = new BufferedReader(new FileReader(users.getPath()));
				String line;
				String lineDecrypted;
				while((line = br.readLine()) != null) {
					lineDecrypted = decryptLine(line);
					String[] tokens = lineDecrypted.split(":");
					if(clientID.equals(tokens[0])) {
						return 1;
					}
				}
				br.close();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			}
			return 0;
		}
		
		private void registaUser(String clientID) throws IOException {
			File users = new File("src\\users.txt");
			BufferedWriter bw = new BufferedWriter(new FileWriter(users, true));
			
			if(clientID.length() != 0) {
				System.out.println("Registo em progresso...");				
				try {
					c.init(Cipher.ENCRYPT_MODE, usersKey);
					String line = clientID + ":" + clientID + "CA.cer";
					String lineEncrypted = encryptLine(line);
					bw.append(lineEncrypted + "\n");
				} catch (InvalidKeyException e) {
					e.printStackTrace();
				}
				
				bw.close();
				Boolean userCreate = new File("users\\" + clientID).mkdir();
				
				Boolean photosCreate = new File("users\\" + clientID + "\\photos").mkdir();
				
				File followers = new File("users\\" + clientID + "\\followers.txt");
				Boolean followersB = followers.createNewFile();
				
				File following = new File("users\\" + clientID + "\\following.txt");
				Boolean followingB = following.createNewFile();
				
				if(!userCreate || !photosCreate || !followersB || !followingB) 
					System.out.println("Erro ao registar utilizador!");
				else 
					System.out.println("Registado com Sucesso!");
			}
		}
		
		private String encryptLine(String line) {
			try {
				byte[] result = line.getBytes("UTF-8");
				return Base64.getEncoder().encodeToString(c.doFinal(result));
			} catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			return null;
		}
		
		private String decryptLine(String line) {
			try {
				return new String(c.doFinal(Base64.getDecoder().decode(line)));
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}
			return null;
		}
		
		@SuppressWarnings("unchecked")
		private void setGroupKey(byte[] key, String groupID, String ownerID) {
			try {
				
				File fileId = new File("groups" + File.separator + groupID + File.separator + "identificador.txt");
				BufferedReader br = new BufferedReader(new FileReader(fileId));
				int identificador = Integer.parseInt(br.readLine());
				
				if(identificador != -1) {
					File keyAntiga = new File("groups" + File.separator + groupID + File.separator + groupID + "Key_" + identificador);
					
					if(keyAntiga.delete()) {
						System.out.println("Deleted file: " + keyAntiga.getName());
					} else {
						System.out.println("Failed to delete the file");
					}
				}
				File groupKey = new File("groups" + File.separator + groupID + File.separator + groupID + "Key_" + (identificador + 1));
				BufferedWriter bw = new BufferedWriter(new FileWriter(fileId));
				bw.append(identificador + 1 +"");
				//Adiciona key ao ownerGroupKeys
				File ownerGroupKeys = new File("groups" + File.separator + groupID + File.separator + ownerID + "-GroupKeys");
				HashMap<Integer, byte[]> keys = new HashMap<>();
				if(ownerGroupKeys.length() != 0) {
					FileInputStream fisOwnerGK = new FileInputStream(ownerGroupKeys);
					ObjectInputStream oisOwnerGK = new ObjectInputStream(fisOwnerGK);				
					keys = (HashMap<Integer, byte[]>) oisOwnerGK.readObject();
					fisOwnerGK.close();
					oisOwnerGK.close();
				}
				keys.put(identificador + 1, key);
				FileOutputStream fosOwnerGK = new FileOutputStream(ownerGroupKeys);
				ObjectOutputStream oosOwnerGK = new ObjectOutputStream(fosOwnerGK);
				oosOwnerGK.writeObject(keys);
				
				
				//Atualiza groupKey
				FileOutputStream fos = new FileOutputStream(groupKey);
				ObjectOutputStream oos = new ObjectOutputStream(fos);
				oos.writeObject(key);
				
				//Fechar canais
				br.close();
				bw.close();
				fosOwnerGK.close();
				oosOwnerGK.close();
				fos.close();
				oos.close();
				
			} catch (IOException | ClassNotFoundException e) {
				e.printStackTrace();
			}
		}
	}
}