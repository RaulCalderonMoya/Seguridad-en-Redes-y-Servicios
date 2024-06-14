import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.Digest;

/**
 * @author Raúl Calderón Moya J10J11
 */

public class Asimetrica {
	public void generarClaves(String ficheroKs, String ficheroKp) {
		// Instanciar el generador de claves
		RSAKeyPairGenerator generadorClaves = new RSAKeyPairGenerator();
		// Generación de parámetros para inicializar el generador de claves
		RSAKeyGenerationParameters parametros = new RSAKeyGenerationParameters(BigInteger.valueOf(17),
				new SecureRandom(), 2048, 10);
		// Inicializar el generador de claves
		generadorClaves.init(parametros);

		//Generar Claves 
		AsymmetricCipherKeyPair claves = generadorClaves.generateKeyPair();
		//Obtener clave privada y publica
		RSAKeyParameters cprivada = (RSAKeyParameters) claves.getPrivate();
		RSAKeyParameters cpublica = (RSAKeyParameters) claves.getPublic();
		//Guardar cada clave en un fichero
		try {
			PrintWriter ficheroPrivada = new PrintWriter(new FileWriter(ficheroKs));
			ficheroPrivada.println(new String(Hex.encode(cprivada.getModulus().toByteArray())));
			ficheroPrivada.print(new String(Hex.encode(cprivada.getExponent().toByteArray())));
			ficheroPrivada.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		try {
			PrintWriter ficheroPublica= new PrintWriter(new FileWriter(ficheroKp));
			ficheroPublica.println(new String(Hex.encode(cpublica.getModulus().toByteArray())));
			ficheroPublica.print(new String(Hex.encode(cpublica.getExponent().toByteArray())));
			ficheroPublica.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	public void cifrar(String tipoClave,String ficheroClave, String ficheroACifrar, String ficheroCifrado) {
		boolean secretaNoSecreta;
		try {
			//Paso 1. Leer el modulo y exponente de la clave
			BufferedReader lectorClaves = new BufferedReader(new FileReader(ficheroClave));
			BigInteger modulo = new BigInteger(Hex.decode(lectorClaves.readLine()));
			BigInteger exponente = new BigInteger(Hex.decode(lectorClaves.readLine()));
			
			if(tipoClave.equals("privada")) {//Clave secreta o privada
				secretaNoSecreta = true; //isPrivate de KeyParameters va a true en este caso al ser clave privada
			}else {//Clave publica
				secretaNoSecreta = false; //isPrivate de KeyParameters va a false en este caso al ser clave publica
			}
			
			//Paso 2.Generacion de parametros para el cifrador
			RSAKeyParameters parametros = new RSAKeyParameters(secretaNoSecreta, modulo, exponente);
			//Paso 3. Instanciar Cifrador 
			AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
			//Paso 4. Inicializar cifrador
			cifrador.init(true, parametros);//True --> Estamos cifrando
			
			BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(ficheroACifrar));
			BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(ficheroCifrado));
			
			byte[] datosCifrados;
		    byte [] datosLeidos = new byte[cifrador.getInputBlockSize()];
		    
		    int leidos = inputStream.read(datosLeidos, 0, cifrador.getInputBlockSize());
		    
		    while(leidos > 0) {
		    	datosCifrados = cifrador.processBlock(datosLeidos, 0, leidos);
		    	leidos = inputStream.read(datosLeidos, 0, cifrador.getInputBlockSize());
		    	outputStream.write(datosCifrados);
		    }
		    outputStream.close();
		    inputStream.close();
		    lectorClaves.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public void descifrar(String tipoClave,String ficheroClave, String ficheroCifrado, String ficheroDescifrado) {
		boolean secretaNoSecreta;
		try {
			BufferedReader lectorClaves = new BufferedReader(new FileReader(ficheroClave));
			BigInteger modulo = new BigInteger(Hex.decode(lectorClaves.readLine()));
			BigInteger exponente = new BigInteger(Hex.decode(lectorClaves.readLine()));
			
			if(tipoClave.equals("privada")) {
				secretaNoSecreta = true;//Clave secreta
			}else {
				secretaNoSecreta = false;//Clave publica
			}
			AsymmetricBlockCipher descifrador = new PKCS1Encoding(new RSAEngine());
			RSAKeyParameters parametros = new RSAKeyParameters(secretaNoSecreta, modulo, exponente);
			descifrador.init(false, parametros);//False --> descifrar
			
			BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(ficheroCifrado));
			BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(ficheroDescifrado));
			
			byte[] datosDescifrados ;
			byte [] datosLeidos = new byte [descifrador.getInputBlockSize()];
			
			int leidos = inputStream.read(datosLeidos, 0, descifrador.getInputBlockSize());
			
			while(leidos> 0) {
				datosDescifrados = descifrador.processBlock(datosLeidos, 0, leidos);
				leidos = inputStream.read(datosLeidos, 0, descifrador.getInputBlockSize());
				outputStream.write(datosDescifrados);
			}
			outputStream.close();
			inputStream.close();
			lectorClaves.close();
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	public void firmar(String ficheroKs, String ficheroAFirmar, String ficheroFirmado) {

		try {
			Digest resumen = new SHA1Digest();
			String resumenHash = "resumen_hash.txt";
			BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(ficheroAFirmar));
			BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(resumenHash));
			
			byte [] datosLeidos = new byte [resumen.getDigestSize()];
			int leidos = inputStream.read(datosLeidos, 0, resumen.getDigestSize());
			
			while(leidos > 0) {
				resumen.update(datosLeidos, 0, leidos);
				leidos = inputStream.read(datosLeidos, 0, resumen.getDigestSize());
			}
			resumen.doFinal(datosLeidos, 0);
			outputStream.write(datosLeidos);
			
			outputStream.close();
			inputStream.close();
			
			//NOTA: Al firmar se cifra con la clave secreta el resumen hash del mensaje m.
			this.cifrar("privada", ficheroKs, resumenHash, ficheroFirmado);
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void verificarFirma(String ficheroKp, String ficheroAFirmar, String ficheroFirmado) {
		
		try {
			Digest resumen = new SHA1Digest();
			BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(ficheroAFirmar));
			byte [] datosLeidos = new byte [resumen.getDigestSize()];
			int leidos = inputStream.read(datosLeidos, 0, resumen.getDigestSize());
			
			while(leidos > 0) {
				resumen.update(datosLeidos, 0, leidos);
				leidos = inputStream.read(datosLeidos, 0, resumen.getDigestSize());
			}
			resumen.doFinal(datosLeidos, 0);
			
			this.descifrar("publica", ficheroKp, ficheroFirmado, "resumen_hash_descifrado.txt");
			
			FileInputStream hashDescifrado = new FileInputStream("resumen_hash_descifrado.txt");
			byte [] datosHashDescifrado = new byte [resumen.getDigestSize()];
			hashDescifrado.read(datosHashDescifrado, 0, resumen.getDigestSize());
			
			hashDescifrado.close();
			
			boolean validacionFirma = Arrays.areEqual(datosLeidos, datosHashDescifrado);
			
			inputStream.close();
			
			if(validacionFirma) {
				System.out.println("*************************");
				System.out.println("Firma realizada con éxito");
				System.out.println("************************");
			}else {
				System.out.println("*************************");
				System.out.println("Proceso de firma fallido");
				System.out.println("************************");
			}
			
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
