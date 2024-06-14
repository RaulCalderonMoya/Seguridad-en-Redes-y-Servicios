package p2;

import java.util.Calendar;
import java.util.GregorianCalendar;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import java.util.Date;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;

/**
 * Esta clase implementa el comportamiento de una CA
 *@author Raúl Calderón Moya
 * @author Seg Red Ser
 * @version 1.0
 */
public class CA {

    private final X500Name nombreEmisor;
    private BigInteger numSerie;
    private final int anosValidez;

    public final static String NOMBRE_FICHERO_CRT = "CertificadoCA.crt";
    public final static String NOMBRE_FICHERO_CLAVES = "CA-claves";

    private RSAKeyParameters clavePrivadaCA = null;
    private RSAKeyParameters clavePublicaCA = null;

    /**
     * Constructor de la CA. Inicializa atributos de la CA a valores por defecto
     */
    public CA() {
        // Distinguished Name DN. C Country, O Organization name, CN Common Name.
        this.nombreEmisor = new X500Name("C=ES, O=DTE, CN=CA");
        this.numSerie = BigInteger.valueOf(1);
        this.anosValidez = 1; // Son los aï¿½os de validez del certificado de usuario, para la CA el valor es
                                // 4
    }

    /**
     * Mï¿½todo que genera la parejas de claves y el certificado autofirmado de la
     * CA.
     *
     * @throws OperatorCreationException
     * @throws IOException
     */
    public void generarClavesyCertificado() throws OperatorCreationException, IOException {
        // Generar una pareja de claves (clase GestionClaves) y guardarlas EN FORMATO
        // PEM en los ficheros
        // indicados por NOMBRE_FICHERO_CLAVES (aï¿½adiendo al nombre las cadenas
        // "_pri.txt" y "_pu.txt")
        //
        // Generar un certificado autofirmado:
        // 1. Configurar parï¿½metros para el certificado e instanciar objeto
        // X509v3CertificateBuilder
        // 2. Configurar hash para resumen y algoritmo firma (MIRAR DIAPOSITIVAS DE
        // APOYO EN MOODLE)
        // 3. Generar certificado
        // 4. Guardar el certificado en formato PEM como un fichero con extensiï¿½n crt
        // (NOMBRE_FICHERO_CRT)
        // COMPLETAR POR EL ESTUDIANTE
        GestionClaves gc = new GestionClaves();
        AsymmetricCipherKeyPair claves = gc.generarClaves(BigInteger.valueOf(3), 2048);// Exponente y tamaño de clave --> Dichos por Pedro en el lab

        this.clavePrivadaCA = (RSAKeyParameters) claves.getPrivate();
        this.clavePublicaCA = (RSAKeyParameters) claves.getPublic();

        PrivateKeyInfo clavePrivadaPkInfo = gc.getClavePrivadaPKCS8(this.clavePrivadaCA);
        SubjectPublicKeyInfo clavePublicaSPKI = gc.getClavePublicaSPKI(this.clavePublicaCA);
        // Ahora las grabamos en los ficheros
        // PKCS8 --> CLAVE PRIVADA SEGUN LA CLASE GESTION OBJETOS PEM
        GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS8KEY_PEM_HEADER, clavePrivadaPkInfo.getEncoded(),
                NOMBRE_FICHERO_CLAVES + "_pri.txt");
        GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PUBLICKEY_PEM_HEADER, clavePublicaSPKI.getEncoded(),
                NOMBRE_FICHERO_CLAVES + "_pu.txt");
        // Guardar claves en formato PEM
        // Vamos primero con la privada -- > PKCS8
        
        Date fechaInicio = new Date(System.currentTimeMillis());
        Calendar c1 = GregorianCalendar.getInstance();
       
        // Devuelve la Date actual. Mismo valor que fecha
       // System.out.println("Fecha Inicio Certificado: " + fechaInicio.toString());

        c1.add(Calendar.YEAR, 4); // aï¿½adir 4 aï¿½os al calendario Para la CA.
        Date fechaFin = c1.getTime();
        // cuatro aï¿½os a partir del momento actual.
        //System.out.println("fecha Fin Certificado :" + fechaFin.toString());

        X509v3CertificateBuilder certBldr = new X509v3CertificateBuilder(nombreEmisor, numSerie, fechaInicio, fechaFin,
                nombreEmisor, clavePublicaSPKI);
        
        //Se añade la extensión basicConstraints al certificado para saber si es o no un certificado de una CA
        //Se limita el camino de certificación a un valor de 5
        BasicConstraints basicConstraints = new BasicConstraints(5);
        certBldr.addExtension(Extension.basicConstraints, true, basicConstraints);

        //Se configura la firma
        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();// Firma
        DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();// Resumen
        AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA");
        AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
        BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
        
       // X509CertificateHolder --> Certificado firmado por la CA
        //X509v3CertificateBuilder --> Certificado sin firmar todavia
        X509CertificateHolder holder =
                certBldr.build(csBuilder.build(this.clavePrivadaCA));
        
        //Guardar en formato PEM
        GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.CERTIFICATE_PEM_HEADER, holder.getEncoded(), NOMBRE_FICHERO_CRT);
    }

    /**
     * Mï¿½todo que carga la parejas de claves
     *
     * @throws IOException
     */
    public void cargarClaves() throws IOException {
        // Carga la pareja de claves de los ficheros indicados por NOMBRE_FICHERO_CLAVES
        // (aï¿½adiendo al nombre las cadenas "_pri.txt" y "_pu.txt")
        // No carga el certificado porque se lee de fichero cuando se necesita.

        GestionClaves gc = new GestionClaves(); // Clase con mï¿½todos para manejar las claves
        // COMPLETAR POR EL ESTUDIANTE
        //Pasar a formato adecuado las claves procedentes de GestionObjetosPEM
        //para despues simplemente modificar el valor de los atributos de clase por los obtenidos
        //de GestionObjetosPEM
        PrivateKeyInfo clavePrivada = (PrivateKeyInfo) GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES+"_pri.txt");
        SubjectPublicKeyInfo clavePublica = (SubjectPublicKeyInfo) GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES+"_pu.txt");
        
        //Pasar de formato de arriba a RSAKeyParameters
        clavePrivadaCA = gc.getClavePrivadaMotor(clavePrivada);
        clavePublicaCA = gc.getClavePublicaMotor(clavePublica);
        
    }

    /**
     * Mï¿½todo que genera el certificado de un usuario a partir de una peticiï¿½n
     * de certificaciï¿½n
     *
     * @param ficheroPeticion:String. Parï¿½metro con la peticiï¿½n de
     *                                certificaciï¿½n
     * @param ficheroCertUsu:String.  Parï¿½metro con el nombre del fichero en el
     *                                que se guardarï¿½ el certificado del usuario
     * @throws IOException
     * @throws PKCSException
     * @throws OperatorCreationException
     */
    public boolean certificarPeticion(String ficheroPeticion, String ficheroCertUsu)
            throws IOException, OperatorCreationException, PKCSException {
         

        // Verificar que estï¿½n generadas las clave privada y pï¿½blica de la CA
        // Verificar firma del solicitante (KPSolicitante en fichero de peticiï¿½n)
        // Si la verificaciï¿½n es ok, se genera el certificado firmado con la clave
        // privada de la CA
        // Se guarda el certificado en formato PEM como un fichero con extensiï¿½n crt

        // COMPLETAR POR EL ESTUDIANTE
        boolean certificadoCorrecto = false;
        GestionClaves gc = new GestionClaves();
        
        //Verificar que las claves de la CA están creadas
		if (clavePrivadaCA != null && clavePublicaCA != null) {
			//Obtener peticion de certificacion que previamente el usuario ha firmado con su clave privada
			//Recuerda que la peticion de certificacion contiene el nombre X500 del usuario en cuestion junto con
			//la firma con la clave secreta del usuario
			PKCS10CertificationRequest peticion = (PKCS10CertificationRequest) GestionObjetosPEM.leerObjetoPEM(ficheroPeticion);
			
			RSAKeyParameters ClavePublicaUsuario = gc.getClavePublicaMotor(peticion.getSubjectPublicKeyInfo());
			
			//Se verifica que la firma está realizada con exito
			//Recuerda que para comprobar una peticion hay que verificar el nombre y firma
			//y para un certificado hay que verificar fecha y firma
    		DefaultDigestAlgorithmIdentifierFinder signer = new DefaultDigestAlgorithmIdentifierFinder();
    		ContentVerifierProvider contentVerifierProvider = new
    				BcRSAContentVerifierProviderBuilder(signer).build(ClavePublicaUsuario);
    		//Verificar Firma
    		if(peticion.isSignatureValid(contentVerifierProvider)){
    			//Añadimos los campos de fechas tanto de inicio como de fin de certicado
    			//Si es certificado autofirmado es de 4 años de validez
    			//y si es un certificado para un usuario es de 1 año para esta práctica
    			Date fechaIniCertificado = new Date(System.currentTimeMillis());
    			Calendar c1 = GregorianCalendar.getInstance();
    			c1.add(GregorianCalendar.YEAR, anosValidez);
    			Date fechaFinCertificado = c1.getTime();
    			
    			//Generar un nuevo certificado
    			X509v3CertificateBuilder certBldr = new X509v3CertificateBuilder(nombreEmisor, numSerie, fechaIniCertificado, fechaFinCertificado, peticion.getSubject(), gc.getClavePublicaSPKI(ClavePublicaUsuario));
    			//SE configura la firma para después poder firmar el certificado con la clave privada de la CA
    			DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
    			DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
    			AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA");
    			AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
    			BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
    			
    			//Certificado firmado por la clave privada de la CA --> CA firma con su clave secreta el certificado del usuario
    			X509CertificateHolder holder = certBldr.build(csBuilder.build(this.clavePrivadaCA));
    			
    			//Almacenar certificado en formato PEM
    			GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.CERTIFICATE_PEM_HEADER, holder.getEncoded(), ficheroCertUsu);
    			certificadoCorrecto = true;
    		}
			
		}
		return certificadoCorrecto;
    }

}
// EL ESTUDIANTE PODRï¿½ CODIFICAR TANTOS Mï¿½TODOS PRIVADOS COMO CONSIDERE
// INTERESANTE PARA UNA MEJOR ORGANIZACIï¿½N DEL Cï¿½DIGO