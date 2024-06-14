package p2;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.OperatorCreationException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequestBuilder;


/**
* Esta clase implementa el comportamiento de un usuario en una Infraestructura de Certificaci�n
* @author Raúl Calderón Moya
* @author Seg Red Ser
* @version 1.0
*/
public class Usuario {
	
	private RSAKeyParameters clavePrivada = null;
	private RSAKeyParameters clavePublica = null;
	
	//NOTA::::::::::::::::.****************************.
	//Para que un certificado sea correcto se tiene que mirar la validez y que la firma sea correcta(que la clave publica de la CA sea la correcta)


	/**
	 * M�todo que genera las claves del usuario.
	 * @param fichClavePrivada: String con el nombre del fichero donde se guardar� la clave privada en formato PEM
	 * @param fichClavePublica: String con el nombre del fichero donde se guardar� la clave publica en formato PEM
     * @throws IOException 	
	
	 */
	public void generarClavesUsuario (String fichClavePrivada, String fichClavePublica) throws IOException{
		
		// Esto es nuevo respecto de la P1. Se debe instanciar un objeto de la clase GestionClaves proporcionada
		// Tanto en Usuario como en CA
		GestionClaves gc = new GestionClaves (); 
		
		// Asignar claves a los atributos correspondientes
		// Escribir las claves en un fichero en formato PEM 

		//IMPLEMENTAR POR EL ESTUDIANTE ESTUDIANTE
		AsymmetricCipherKeyPair claves = gc.generarClaves(BigInteger.valueOf(3), 2048);
		
		this.clavePrivada = (RSAKeyParameters) claves.getPrivate();
		this.clavePublica = (RSAKeyParameters) claves.getPublic();
		
		PrivateKeyInfo clavePrivada = gc.getClavePrivadaPKCS8(this.clavePrivada);
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS8KEY_PEM_HEADER, clavePrivada.getEncoded(), fichClavePrivada);
		
		SubjectPublicKeyInfo clavePublica = gc.getClavePublicaSPKI(this.clavePublica);
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PUBLICKEY_PEM_HEADER, clavePublica.getEncoded(), fichClavePublica);
    }



	
	/**
	 * M�todo que genera una petici�n de certificado en formato PEM, almacenando esta petici�n en un fichero.
	 * @param fichPeticion: String con el nombre del fichero donde se guardar� la petici�n de certificado
	 * @throws IOException 
	 * @throws OperatorCreationException 
	 */
	public void crearPetCertificado(String fichPeticion) throws OperatorCreationException, IOException {
		// IMPLEMENTAR POR EL ESTUDIANTE
	   	// Configurar hash para resumen y algoritmo firma (MIRAR DIAPOSITIVAS PRESENTACI�N PR�CTICA)
		// La solicitud se firma con la clave privada del usuario y se escribe en fichPeticion en formato PEM
		// IMPLEMENTAR POR EL ESTUDIANTE
		if (this.clavePrivada != null && this.clavePublica != null) {
			//En una peticion de certificado se incluye el nombre de la entidad
			//y la clave publica del usuario
			X500Name nombrePropietario = new X500Name("C=ES, O=DTE, CN=Raul");
			GestionClaves gc = new GestionClaves();
			//Se obtiene la clave publica de los atributos de clase porque es la del propio usuario la que 
			//se utiliza
			SubjectPublicKeyInfo clavePublica = gc.getClavePublicaSPKI(this.clavePublica);
			//Creacion de peticion de certificado --> Nombre X.500 + clave publica del usuario
			PKCS10CertificationRequestBuilder requestBuilder = new PKCS10CertificationRequestBuilder(nombrePropietario, clavePublica);
			
			//Se configura la firma
			DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
			DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
			AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA");
			AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
			BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
			//Peticion de certificado firmada por la clave Privada pero no de la CA sino la clave privada del usuario
			PKCS10CertificationRequest pet= 
			requestBuilder.build(csBuilder.build(this.clavePrivada));
			
			//Almacenar informacion en formato pem de la peticion de certificacion
			GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS10_PEM_HEADER, pet.getEncoded(), fichPeticion);
		}else {
			System.out.println("No tengo las claves, Ha fallado en Usuario método crearPetCertificado");
		}
	}
	
	
	/**
	 * M�todo que verifica un certificado de una entidad.
	 * @param fichCertificadoCA: String con el nombre del fichero donde se encuentra el certificado de la CA
	 * @param fichCertificadoUsu: String con el nombre del fichero donde se encuentra el certificado de la entidad
     	 * @throws CertException 
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 * @throws FileNotFoundException 	
	 * @return boolean: true si verificaci�n OK, false en caso contrario.
	 */
    public boolean verificarCertificadoExterno(String fichCertificadoCA, String fichCertificadoUsu)throws OperatorCreationException, CertException, FileNotFoundException, IOException {

    // IMPLEMENTAR POR EL ESTUDIANTE
	// Comprobar fecha validez del certificado
	// Si la fecha es v�lida, se comprueba la firma
	// Generar un contenedor para la verificaci�n con la clave p�blica de CA,
	// el certificado del usuario tiene el resto de informaci�n
    	
   	// IMPLEMENTAR POR EL ESTUDIANTE
    	boolean certificadoCorrecto = false;
    	//Obtenemos un certificado que ha sido firmado
    	X509CertificateHolder certUsuario = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoUsu);
    	
    	
    	//Primero hay que comprobar la fecha del usuario
    	Calendar c1 = GregorianCalendar.getInstance();
    	Date fechaActual = c1.getTime();
    	//Creación objeto gc de tipo GestionClaves
    	GestionClaves gc = new GestionClaves();
    	
    	//Recordemos que para verificar un certificado hay que verificar la fecha del certificado
    	//que esté en periodo de validez 
    	if(fechaActual.after(certUsuario.getNotBefore())&& fechaActual.before(certUsuario.getNotAfter())) {
    		X509CertificateHolder certCA = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoCA);
    		RSAKeyParameters clavePublicaCA = gc.getClavePublicaMotor(certCA.getSubjectPublicKeyInfo());
    		DefaultDigestAlgorithmIdentifierFinder signer = new DefaultDigestAlgorithmIdentifierFinder();
    		//Se verifica la firma del certificado --> Para verificar la firma de un certificado de usuario
    		//al haber sido firmado previamente al expedir el certificado por la clave privada de la CA, entonces
    		//ahora hay que obtener la clave publica para verificar dicha firma digital
    		ContentVerifierProvider contentVerifierProvider = new
    				BcRSAContentVerifierProviderBuilder(signer).build(clavePublicaCA);
    		certificadoCorrecto =certUsuario.isSignatureValid(contentVerifierProvider);
    	}
    	return certificadoCorrecto;
	}	
}

	// EL ESTUDIANTE PODR� CODIFICAR TANTOS M�TODOS PRIVADOS COMO CONSIDERE INTERESANTE PARA UNA MEJOR ORGANIZACI�N DEL C�DIGO