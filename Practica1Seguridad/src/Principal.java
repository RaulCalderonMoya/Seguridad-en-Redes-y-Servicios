/**Fichero: Principal.java
 * Clase para comprobar el funcionamiento de las otras clases del paquete.
 * Asignatura: SEG
 * @author Profesores de la asignatura
 * @version 1.0
 */

import java.util.Scanner;

/**
 * @author Raúl Calderón Moya J10J11
 */
public class Principal {

	public static void main (String [ ] args) {
		int menu1;
		int menu2;
		Scanner sc = new Scanner(System.in);
		/* completar declaracion de variables e instanciación de objetos */
		Simetrica simetrica = new Simetrica();
		String ficheroClave;
		String ficheroACifrar;
		String ficheroCifrado;
		String ficheroDescifrado;
		
		//Parte de Criptografía asimétrica
		String ficheroKs;
		String ficheroKp;
		Asimetrica asimetrica = new Asimetrica();
		String tipoClave;
		
		//Parte de Firma digital
		String ficheroAFirmar;
		String ficheroFirmado;
		
		do {
			System.out.println("¿Qué tipo de criptografía desea utilizar?");
			System.out.println("1. Simétrico.");
			System.out.println("2. Asimétrico.");
			System.out.println("3. Salir.");
			menu1 = sc.nextInt();
		
			switch(menu1){
				case 1:
					do{
						System.out.println("Elija una opción para CRIPTOGRAFIA SIMÉTRICA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:
								/*completar acciones*/
								System.out.println("Introduzca el nombre del fichero con la clave");
								ficheroClave = sc.next();
								simetrica.generarClave(ficheroClave);
							break;
							case 2:
								/*completar acciones*/
								System.out.println("Introduzca el nombre del fichero con la clave");
								ficheroClave = sc.next();
								System.out.println("Introduzca el nombre del fichero a cifrar (Fichero En Claro)");
								ficheroACifrar = sc.next();
								System.out.println("Introduzca el nombre del fichero cifrado");
								ficheroCifrado = sc.next();
								simetrica.cifrar(ficheroClave, ficheroACifrar, ficheroCifrado);
							break;
							case 3:
								/*completar acciones*/
								System.out.println("Introduzca el nombre del fichero con la clave");
								ficheroClave = sc.next();
								System.out.println("Introduzca el nombre del fichero a descifrar (Fichero Cifrado)");
								ficheroCifrado = sc.next();
								System.out.println("Introduzca el nombre del fichero descifrado");
								ficheroDescifrado = sc.next();
								simetrica.descifrar(ficheroClave, ficheroCifrado, ficheroDescifrado);
							break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Elija una opción para CRIPTOGRAFIA ASIMÉTRICA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						System.out.println("4. Firmar digitalmente.");
						System.out.println("5. Verificar firma digital.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:
								/*completar acciones*/
								System.out.println("Introduzca el nombre del fichero de la clave secreta");
								ficheroKs = sc.next();
								System.out.println("Introduzca el nombre del fichero de la clave publica");
								ficheroKp = sc.next();
								asimetrica.generarClaves(ficheroKs, ficheroKp);
							break;
							case 2:
								/*completar acciones*/
								System.out.println("Indique la clave que desea usar para cifrar [privada/publica]");
								tipoClave = sc.next();
								System.out.println("Introduzca el nombre del fichero a cifrar (Fichero En Claro)");
								ficheroACifrar = sc.next();
								System.out.println("Introduzca el nombre del fichero cifrado");
								ficheroCifrado = sc.next();
								System.out.println("Introduzca el nombre del fichero con la clave del tipo indicado anteriormente para cifrar (Fichero Clave [Pública/Privada])");
								switch(tipoClave) {
								case "privada":
									ficheroKs = sc.next();
									asimetrica.cifrar(tipoClave,ficheroKs, ficheroACifrar, ficheroCifrado);
									//Se pasa el tipoClave porque el metodo RSAKeyGenParameters tiene un 
									//parametro para saber si es on privada la clave
									//En ese metodo boolean isPrivate si es true --> privada y de lo contrario es publica
									break;
								case "publica":
									ficheroKp = sc.next();
									asimetrica.cifrar(tipoClave,ficheroKp, ficheroACifrar, ficheroCifrado);
									//Se pasa el tipoClave porque el metodo RSAKeyGenParameters tiene un 
									//parametro para saber si es on privada la clave
									//En ese metodo boolean isPrivate si es true --> privada y de lo contrario es publica
									break;
								}
							break;
							case 3:
								/*completar acciones*/
								/*completar acciones*/
								System.out.println("Recuerde que si cifró con la publica debe descifrar con la secreta y viceversa");
								System.out.println("Indique la clave que desea usar para descifrar [privada/publica]");
								tipoClave = sc.next();
								System.out.println("Introduzca el nombre del fichero a descifrar (Fichero que ha cifrado previamente)");
								ficheroCifrado = sc.next();
								System.out.println("Introduzca el nombre del fichero descifrado");
								ficheroDescifrado = sc.next();
								System.out.println("Introduzca el nombre del fichero con la clave del tipo indicado anteriormente para descifrar (Fichero Clave [Pública/Privada])");
								switch(tipoClave) {
								case "privada":
									ficheroKs = sc.next();
									asimetrica.descifrar(tipoClave,ficheroKs, ficheroCifrado, ficheroDescifrado);
									//Se pasa el tipoClave porque el metodo RSAKeyGenParameters tiene un 
									//parametro para saber si es on privada la clave
									//En ese metodo boolean isPrivate si es true --> privada y de lo contrario es publica
									break;
								case "publica":
									ficheroKp = sc.next();
									asimetrica.descifrar(tipoClave,ficheroKp, ficheroCifrado, ficheroDescifrado);
									//Se pasa el tipoClave porque el metodo RSAKeyGenParameters tiene un 
									//parametro para saber si es on privada la clave
									//En ese metodo boolean isPrivate si es true --> privada y de lo contrario es publica
									break;
								}
							break;
							case 4:
								/*completar acciones*/
								System.out.println("Introduzca el nombre del fichero con la clave secreta");
								ficheroKs = sc.next();
								System.out.println("Introduzca el nombre del fichero a firmar (Fichero En Claro)");
								ficheroAFirmar = sc.next();
								System.out.println("Introduzca el nombre del fichero firmado");
								ficheroFirmado = sc.next();
								
								//Llamada al metodo de firmar
								asimetrica.firmar(ficheroKs, ficheroAFirmar, ficheroFirmado);
								
							break;
							case 5:
								/*completar acciones*/
								System.out.println("Introduzca el nombre del fichero con la clave publica");
								ficheroKp = sc.next();
								System.out.println("Introduzca el nombre del fichero de datos (Fichero En Claro)");
								ficheroAFirmar = sc.next();
								System.out.println("Introduzca el nombre del fichero firmado");
								ficheroFirmado = sc.next();
								
								//Llamada al metodo de verificarFirma
								asimetrica.verificarFirma(ficheroKp, ficheroAFirmar, ficheroFirmado);
								
							break;
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
		sc.close();
	}
}