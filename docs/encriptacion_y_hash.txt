# ENCRIPTACIÓN Y FUNCIONES HASH: HISTORIA, TIPOS, APLICACIONES Y CONSIDERACIONES ÉTICAS

## Historia de la Encriptación

La encriptación tiene una historia milenaria que se remonta a las antiguas civilizaciones. A lo largo del tiempo, ha evolucionado desde métodos simples hasta complejos algoritmos matemáticos:

### Antigüedad y Edad Media
- **Cifrado por sustitución (Siglo V a.C.)**: Los espartanos utilizaban el "escítalo", un bastón alrededor del cual se enrollaba una tira de cuero con un mensaje.
- **Cifrado César (Siglo I a.C.)**: Julio César utilizaba un sistema simple donde cada letra se reemplazaba por otra situada un número fijo de posiciones más adelante en el alfabeto.
- **Cifrado de Al-Kindi (Siglo IX)**: El matemático árabe Al-Kindi desarrolló técnicas de criptoanálisis y escribió el "Manuscrito para Descifrar Mensajes Criptográficos".
- **Disco de Alberti (Siglo XV)**: Leon Battista Alberti inventó el primer sistema polialfabético, considerado el padre de la criptografía occidental.

### Era Moderna
- **Máquina Enigma (1918-1945)**: Utilizada por los alemanes durante la Segunda Guerra Mundial, representó un avance significativo en la complejidad de la encriptación.
- **Desarrollo de DES (1975)**: El Data Encryption Standard fue el primer estándar de encriptación ampliamente adoptado para uso comercial.
- **Invención de RSA (1977)**: Rivest, Shamir y Adleman desarrollaron el primer algoritmo práctico de clave pública, revolucionando la criptografía.
- **Adopción de AES (2001)**: El Advanced Encryption Standard reemplazó a DES como el estándar de encriptación simétrica.
- **Encriptación Post-Cuántica (Actualidad)**: Desarrollo de algoritmos resistentes a ataques de computadoras cuánticas.

## Tipos de Encriptación: Origen, Problemas que Resuelven y Ejemplos

### 1. Encriptación Simétrica

La **encriptación simétrica** es un método criptográfico en el que se utiliza una única clave secreta para cifrar (convertir información en un formato ilegible) y descifrar (recuperar la información original) los datos. Esta clave debe ser conocida únicamente por las partes involucradas en la comunicación.

En otras palabras, imagina que tienes una caja fuerte con una cerradura especial. Para guardar algo dentro y luego sacarlo, utilizas la misma llave. Si alguien más obtiene esta llave, podrá abrir la caja fuerte y acceder a su contenido. Por eso, es fundamental proteger y compartir esta clave de manera segura.

**Características principales**:
- Utiliza una sola clave secreta compartida.
- Es rápida y eficiente, ideal para cifrar grandes cantidades de datos.
- Requiere un método seguro para compartir la clave entre las partes involucradas.

**Ejemplos comunes**:
- **AES (Advanced Encryption Standard)**: Actualmente el estándar más utilizado, con claves de 128, 192 o 256 bits.
- **DES (Data Encryption Standard)**: Un estándar antiguo con claves de 56 bits, ahora considerado inseguro.
- **3DES (Triple DES)**: Una mejora del DES que aplica el cifrado tres veces para aumentar la seguridad.
- **Blowfish y Twofish**: Alternativas populares por su velocidad y seguridad.

**Aplicaciones prácticas**:
- Protección de datos almacenados en discos duros o bases de datos.
- Comunicación segura en redes privadas.
- Cifrado de archivos y documentos sensibles.


**Origen**: Surgió como el primer tipo de encriptación formal. Los métodos simétricos han existido desde la antigüedad, pero se formalizaron matemáticamente en el siglo XX.

**Problemas que resuelve**:
- Protección de la confidencialidad de datos en reposo y en tránsito
- Encriptación eficiente de grandes volúmenes de datos
- Necesidad de procesamiento rápido en sistemas con recursos limitados

**Por qué surgió**:
La necesidad de comunicaciones secretas, especialmente en contextos militares y diplomáticos, impulsó el desarrollo de estos métodos. Durante la era de la computación, se necesitaban algoritmos estandarizados que pudieran implementarse en hardware y software.

**Ejemplos**:
- **DES (Data Encryption Standard)**: Desarrollado en los años 70, fue el primer estándar ampliamente adoptado. Utilizaba una clave de 56 bits, que eventualmente se volvió vulnerable a ataques de fuerza bruta.
- **3DES (Triple DES)**: Surgió como solución temporal a las debilidades de DES, aplicando el algoritmo tres veces con diferentes claves.
- **AES (Advanced Encryption Standard)**: Desarrollado para reemplazar a DES, utiliza claves de 128, 192 o 256 bits y es actualmente el estándar más utilizado globalmente.
- **Blowfish y Twofish**: Alternativas a AES, diseñadas para ser eficientes y seguras en diversas plataformas.


![Visualización de Encriptación Simétrica](assets/visual_selection.png)



### 2. Encriptación Asimétrica (o de Clave Pública)

**Origen**: Surgió en la década de 1970 como respuesta a las limitaciones de la encriptación simétrica, particularmente el problema del intercambio seguro de claves.

**Problemas que resuelve**:
- El problema del intercambio de claves: permite a partes que nunca se han comunicado antes establecer un canal seguro
- Posibilita las firmas digitales, proporcionando autenticidad e integridad
- Permite la no repudiación en comunicaciones digitales
- Facilita la autenticación sin compartir secretos

**Por qué surgió**:
Con el aumento de las redes de computadoras, surgió la necesidad de establecer comunicaciones seguras entre partes que nunca habían tenido contacto previo. La encriptación simétrica requería un canal seguro preexistente para intercambiar claves, creando un círculo vicioso.

**Ejemplos**:
- **RSA**: Nombrado por sus creadores (Rivest, Shamir, Adleman), se basa en la dificultad de factorizar números grandes. Es el algoritmo asimétrico más utilizado históricamente.
- **ECC (Elliptic Curve Cryptography)**: Ofrece la misma seguridad que RSA con claves más pequeñas, haciéndolo ideal para dispositivos con recursos limitados.
- **DSA (Digital Signature Algorithm)**: Diseñado específicamente para firmas digitales, no para encriptación.
- **ElGamal**: Basado en el problema del logaritmo discreto, utilizado tanto para encriptación como para firmas digitales.

### 3. Encriptación Híbrida

**Origen**: Surgió como una solución práctica para combinar las ventajas de los sistemas simétricos y asimétricos, eliminando sus respectivas desventajas.

**Problemas que resuelve**:
- La ineficiencia de la encriptación asimétrica para grandes volúmenes de datos
- El problema del intercambio de claves de la encriptación simétrica
- La necesidad de sistemas prácticos y eficientes para comunicaciones seguras a gran escala

**Por qué surgió**:
A medida que las aplicaciones de seguridad se volvieron más complejas, se hizo evidente que ningún sistema por sí solo era óptimo. La encriptación asimétrica es demasiado lenta para grandes volúmenes de datos, mientras que la simétrica tiene problemas con la distribución de claves.

**Ejemplos**:
- **TLS/SSL**: Utilizado en HTTPS para asegurar las comunicaciones web, utiliza RSA o ECC para intercambiar una clave simétrica, que luego se utiliza con AES para la comunicación.
- **PGP (Pretty Good Privacy)**: Utilizado para correo electrónico seguro, combina RSA para el intercambio de claves con algoritmos simétricos para el cifrado de mensajes.
- **Signal Protocol**: Utilizado en aplicaciones de mensajería como WhatsApp y Signal, combina encriptación asimétrica para establecer claves y simétrica para las comunicaciones continuas.

## ¿Qué son las Funciones Hash?

Una función hash es un algoritmo matemático que transforma datos de entrada de longitud variable en una cadena de salida de longitud fija, conocida como "hash", "digest" o "huella digital". A diferencia de la encriptación, el proceso de hash es unidireccional, lo que significa que no está diseñado para ser revertido.

### Historia y Evolución de las Funciones Hash

- **1950s-1960s**: Primeras funciones hash para verificación de datos y tablas hash en computación.
- **1979**: Primeras funciones hash criptográficas formales por Rabin y Merkle.
- **1991**: MD5 desarrollado por Ron Rivest, ampliamente utilizado hasta que se encontraron vulnerabilidades.
- **1993-1995**: SHA (Secure Hash Algorithm) desarrollado por la NSA.
- **2002-2005**: Descubrimiento de colisiones en MD5 y SHA-1, impulsando el desarrollo de algoritmos más seguros.
- **2012**: Adopción de SHA-3 (basado en Keccak) como nuevo estándar.

### Características de las Funciones Hash

1. **Determinismo**: La misma entrada siempre produce el mismo hash de salida
2. **Unidireccionalidad**: Es computacionalmente inviable recuperar los datos originales a partir del hash
3. **Efecto avalancha**: Un pequeño cambio en la entrada produce un cambio significativo en la salida
4. **Resistencia a colisiones**: Es difícil encontrar dos entradas diferentes que produzcan el mismo hash
5. **Distribución uniforme**: Los valores hash se distribuyen uniformemente en el espacio de salida

### Aplicaciones de las Funciones Hash

1. **Verificación de integridad**: Detectar si un archivo o mensaje ha sido modificado
2. **Almacenamiento seguro de contraseñas**: Las contraseñas se almacenan como hashes, no en texto plano
3. **Firmas digitales**: Verificar la autenticidad e integridad de mensajes y documentos
4. **Estructuras de datos**: Tablas hash, árboles Merkle, etc.
5. **Blockchain y criptomonedas**: Prueba de trabajo, encadenamiento de bloques

### Algoritmos Hash Comunes

1. **MD5 (Message Digest Algorithm 5)**:
   - Produce un hash de 128 bits
   - Ya no se considera seguro para aplicaciones criptográficas debido a vulnerabilidades

2. **SHA (Secure Hash Algorithm)**:
   - SHA-1: Produce un hash de 160 bits (considerado inseguro)
   - SHA-2: Incluye SHA-256 (256 bits) y SHA-512 (512 bits)
   - SHA-3: El estándar más reciente, basado en el algoritmo Keccak

3. **BLAKE2**:
   - Más rápido que MD5, SHA-1, SHA-2 y SHA-3
   - Optimizado para plataformas de 64 bits

4. **bcrypt, scrypt, Argon2**:
   - Funciones hash diseñadas específicamente para contraseñas
   - Incluyen "salt" y son deliberadamente lentas para dificultar ataques de fuerza bruta

## Diferencias entre Encriptación y Hash

| Característica | Encriptación | Hash |
|----------------|--------------|------|
| Reversibilidad | Reversible con la clave correcta | No reversible |
| Propósito principal | Confidencialidad | Integridad y autenticación |
| Tamaño de salida | Variable o proporcional a la entrada | Fijo |
| Uso de claves | Requiere claves | No requiere claves (aunque puede usar "salt") |
| Aplicaciones típicas | Comunicaciones seguras, almacenamiento de datos | Verificación de integridad, almacenamiento de contraseñas |

## Importancia en la Seguridad Informática

La encriptación y las funciones hash son pilares fundamentales de la seguridad informática moderna. Juntas, proporcionan:

1. **Confidencialidad**: Protección de datos sensibles contra accesos no autorizados
2. **Integridad**: Garantía de que los datos no han sido alterados
3. **Autenticación**: Verificación de la identidad de usuarios y sistemas
4. **No repudio**: Evidencia de que una acción fue realizada por un usuario específico

En el mundo actual, donde las amenazas cibernéticas son cada vez más sofisticadas, comprender y aplicar correctamente estos conceptos es esencial para desarrollar sistemas seguros y proteger la información sensible.

## Consideraciones Éticas y Legales

El uso de encriptación y técnicas criptográficas está sujeto a regulaciones en muchos países. Algunos aspectos a considerar:

1. **Exportación de tecnología criptográfica**: Restricciones en ciertos países
2. **Acceso gubernamental**: Debates sobre "puertas traseras" y acceso a datos encriptados
3. **Uso dual**: La misma tecnología que protege datos legítimos puede ser usada por actores maliciosos
4. **Privacidad vs. Seguridad**: El equilibrio entre la privacidad individual y la seguridad nacional

Es importante mantenerse informado sobre las leyes y regulaciones aplicables al desarrollar o implementar soluciones que utilicen encriptación o funciones hash.