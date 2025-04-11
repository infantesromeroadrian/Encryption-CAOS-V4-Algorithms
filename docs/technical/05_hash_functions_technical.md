# Informe Técnico: Funciones Hash Criptográficas

## 1. Introducción

Las funciones hash criptográficas son algoritmos matemáticos que transforman datos de entrada de tamaño arbitrario en una salida de tamaño fijo (hash). Estas funciones son fundamentales en criptografía moderna, proporcionando integridad de datos, autenticación y seguridad en diversos sistemas.

## 2. Propiedades Matemáticas Fundamentales

### 2.1 Propiedades de las Funciones Hash

#### Resistencia a Preimagen
- Dado un hash h, es computacionalmente inviable encontrar m tal que H(m) = h
- Complejidad: O(2^n) para hash de n bits
- Importancia para almacenamiento de contraseñas

#### Resistencia a Segunda Preimagen
- Dado m1, es inviable encontrar m2 ≠ m1 tal que H(m1) = H(m2)
- Protección contra suplantación de mensajes
- Base para firmas digitales

#### Resistencia a Colisiones
- Es inviable encontrar dos mensajes distintos m1, m2 con H(m1) = H(m2)
- Requisito más fuerte que resistencia a segunda preimagen
- Importante para certificados digitales

### 2.2 Estructuras de Construcción

#### Construcción Merkle-Damgård
- Procesamiento iterativo de bloques
- Función de compresión interna
- Padding específico para completar el último bloque
- Ejemplos: MD5, SHA-1, SHA-2

#### Construcción Sponge
- Dos fases: absorción y exprimido
- Mayor flexibilidad en tamaño de salida
- Resistente a ataques de longitud extendida
- Ejemplo: SHA-3 (Keccak)

## 3. Algoritmos Principales

### 3.1 SHA-2 Family

#### SHA-256
- Longitud de hash: 256 bits
- 64 rondas de procesamiento
- Estructura de bloques de 512 bits
- Ampliamente utilizado en blockchain

#### SHA-512
- Longitud de hash: 512 bits
- 80 rondas de procesamiento
- Estructura de bloques de 1024 bits
- Mayor seguridad que SHA-256

### 3.2 SHA-3 (Keccak)

#### Características
- Construcción sponge
- Permutación Keccak-f
- Tamaños de hash: 224, 256, 384, 512 bits
- Resistente a ataques de longitud extendida

## 4. Aplicaciones Criptográficas

### 4.1 Almacenamiento de Contraseñas

#### Proceso de Hashing
- Aplicación de salt único
- Múltiples iteraciones (key stretching)
- Uso de funciones lentas (bcrypt, Argon2)

#### Consideraciones de Seguridad
- Protección contra rainbow tables
- Resistencia a GPU/ASIC
- Gestión de salt

### 4.2 Firmas Digitales

#### Proceso de Firma
- Hash del mensaje
- Encriptación con clave privada
- Verificación con clave pública

#### Seguridad
- Resistencia a colisiones crítica
- Longitud de hash adecuada
- Actualización periódica de algoritmos

## 5. Análisis de Seguridad

### 5.1 Ataques Comunes

#### Ataques de Cumpleaños
- Probabilidad de colisión: √(2^n)
- Reducción efectiva de bits de seguridad
- Mitigación con hashes más largos

#### Ataques de Longitud Extendida
- Explotación de construcción Merkle-Damgård
- Prevención con construcción sponge
- Uso de HMAC

### 5.2 Métricas de Seguridad

#### Longitud de Hash
- SHA-256: 128 bits de seguridad
- SHA-512: 256 bits de seguridad
- Consideraciones para computación cuántica

#### Rendimiento
- Velocidad de procesamiento
- Uso de memoria
- Paralelización

## 6. Implementación Práctica

### 6.1 Consideraciones de Diseño

#### Elección de Algoritmo
- Requisitos de seguridad
- Restricciones de rendimiento
- Compatibilidad con sistemas existentes

#### Manejo de Errores
- Validación de entrada
- Gestión de memoria
- Recuperación de fallos

### 6.2 Optimizaciones

#### Hardware
- Instrucciones específicas (SHA-NI)
- Aceleración por GPU
- Implementaciones ASIC

#### Software
- Algoritmos optimizados
- Caching de resultados
- Procesamiento por lotes

## 7. Conclusiones

Las funciones hash criptográficas son componentes esenciales en sistemas seguros modernos. Su implementación requiere:

- Comprensión profunda de propiedades matemáticas
- Selección cuidadosa de algoritmos
- Consideración de amenazas actuales y futuras
- Balance entre seguridad y rendimiento

La evolución continua de estas funciones es crucial para mantener la seguridad en un entorno tecnológico en constante cambio. 