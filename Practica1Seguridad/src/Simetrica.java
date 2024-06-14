import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.PaddedBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.X923Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * @author Raúl Calderón Moya J10J11
 */

public class Simetrica {
	
	public void generarClave(String ficheroClave) {
		//1. Crear objeto generador
		CipherKeyGenerator generador = new CipherKeyGenerator();
		//2. Inicializar objeto generador
		KeyGenerationParameters parametros = new KeyGenerationParameters(new SecureRandom(), 512);//512 bits es el tamaño de la clave
		//Los parametros es la informacion que necesita el generador para crear una clave de 512 bits.
		generador.init(parametros);
		//3.Generar clave y 4. Convertir clave a Hexadecimal
		byte [] clave = Hex.encode(generador.generateKey());//Aqui almaceno el array de bytes de la clave ya en Hexadecimal.
		//5. Almacenar clave en fichero
		FileOutputStream salida = null;
		try {
			salida = new FileOutputStream(ficheroClave);
			salida.write(clave);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally {
			if(salida != null) {
				try {
					salida.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
	}
	
	public void cifrar(String ficheroClave, String ficheroACifrar, String ficheroCifrado) {
		try {
			//Paso 1. Leer Clave y decodificar de Hex a bin
			BufferedReader br = new BufferedReader(new FileReader(ficheroClave));
			String valorClave = br.readLine();
			byte [] clave = Hex.decode(valorClave);//Pasamos de Hexadecimal a binario la clave
			//Paso 2. Generar parámetros y cargar clave
			KeyParameter params = new KeyParameter(clave);//Convierte la clave en algo que entiende el motor de cifrado. En si es la clave sin más.
			//Paso 3. Crear motor de cifrado cons los datos del enunciado
			//PaddedBufferedBlockCipher --> Cifrador en bloque con relleno.                       //ThreeFishEngine admite solo bloques de 512 bytes.
			PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new ThreefishEngine(512)), new X923Padding());
			//Paso 4. Iniciar motor de cifrado con params
			cifrador.init(true, params);//True --> Estamos cifrando
			//Paso 5. Crear flujos E/S ficheros
			BufferedInputStream bufferEntrada = new BufferedInputStream(new FileInputStream(ficheroACifrar));
			BufferedOutputStream bufferSalida = new BufferedOutputStream(new FileOutputStream(ficheroCifrado));
			//Paso 6. Crear arrays de bytes para E/S: datosLeidos, datosCifrados --> Permiten almacenar datos que leen de fichero o cifrados para escribir en otro fichero después.
			byte [] datosLeidos = new byte[cifrador.getBlockSize()];//Le doy 512 bits porque es el tamaño de bloque que vamos leyendo
			byte [] datosCifrados = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];//Le doy el doble de tamaño respecto al anterior
			//Paso 7. Bucle de lectura, cifrado y escritura
			int leidos = bufferEntrada.read(datosLeidos, 0, cifrador.getBlockSize());
			int cifrados;
			while(leidos > 0 ){
				cifrados = cifrador.processBytes(datosLeidos, 0, leidos, datosCifrados, 0);//El processBytes cifra los datos
				//Array de bytes de entrada // offset // donde los leo // Array de bytes de salida // offset
				bufferSalida.write(datosCifrados, 0, cifrados);
				leidos = bufferEntrada.read(datosLeidos, 0, cifrador.getBlockSize());
				//Lee 512 bits y cuando quede alguno que no sea de 512 bits entonces ya sale del bucle
			}
			//El tamaño del ultimo bloque es el doble ya que devuelve el cifrado(512 bits) junto con el relleno dando lugar al doble de tamaño
			//de ahi que el tamaño del buffer de salida sea el doble que el de entrada para que el ultimo quepa.
			cifrados = cifrador.doFinal(datosCifrados, 0);
			bufferSalida.write(datosCifrados, 0, cifrados);
			
			//Paso 8. Cerrar Ficheros
			bufferSalida.close();
			bufferEntrada.close();
			br.close();
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DataLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
				
		
	}
	
	public void descifrar(String ficheroClave, String ficheroCifrado, String ficheroDescifrado) {
		try {
			//Paso 1. Leer clave y decodificar de Hex a bin
			BufferedReader br = new BufferedReader(new FileReader(ficheroClave));
			String valorClave = br.readLine();
			byte[] clave = Hex.decode(valorClave);
			//Paso 2. Generar parámetros y cargar clave
			KeyParameter params = new KeyParameter(clave);
			//Paso 3. Crear motor de cifrado con los datos del enunciado
			PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new ThreefishEngine(512)), new X923Padding());
			//Paso 4. Iniciar motor de cifrado con params
			cifrador.init(false, params);//False --> Estamos descifrando
			//Paso 5. Crear flujos E/S ficheros
			BufferedInputStream bufferEntrada = new BufferedInputStream(new FileInputStream(ficheroCifrado));
			BufferedOutputStream bufferSalida = new BufferedOutputStream(new FileOutputStream(ficheroDescifrado));
			//Paso 6. Crear arrays de bytes para E/S: datosLeidos y datosCifrados
			byte [] datosLeidos = new byte[cifrador.getBlockSize()];
			byte [] datosDesCifrados = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];
			//Paso 7. Bucle de lecturam cifrado y escritura
			int leidos = bufferEntrada.read(datosLeidos, 0, cifrador.getBlockSize());
			int descifrados;
			while(leidos > 0) {
				descifrados = cifrador.processBytes(datosLeidos, 0, leidos, datosDesCifrados, 0);
			    bufferSalida.write(datosDesCifrados, 0, descifrados);
			    leidos = bufferEntrada.read(datosLeidos, 0, cifrador.getBlockSize());
			}
			descifrados = cifrador.doFinal(datosDesCifrados, 0);
			bufferSalida.write(datosDesCifrados, 0, descifrados);
			
			//Paso 8. Cerrar Ficheros
			bufferSalida.close();
			bufferEntrada.close();
			br.close();
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DataLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	
}
