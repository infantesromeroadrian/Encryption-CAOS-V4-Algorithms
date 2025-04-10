# Diagramas de CAOS V4 - Versión Técnica y Amigable

## Arquitectura de Tres Capas (Técnico) / ¿Cómo Protege CAOS V4 tus Secretos? (Amigable)

```mermaid
flowchart TD
    subgraph "Capa 1: Derivación PBKDF2"
        A[Contraseña] --> B[Sal - Sello Especial]
        B --> C[PBKDF2 - Proceso de Mezcla]
        C --> D[Clave AES - Llave Maestra]
    end
    
    subgraph "Capa 2: Cifrado AES-GCM"
        E[Datos] --> F[AES-GCM - Caja Fuerte Digital]
        D --> F
        G[Nonce - Número Aleatorio] --> F
        F --> H[Cifrado+Tag - Secreto Protegido]
    end
    
    subgraph "Capa 3: Transporte"
        B --> I[Metadatos - Paquete Seguro]
        G --> I
        H --> I
        I --> J[Mensaje Final]
    end
```

## Estructura del Mensaje (Técnico) / ¿Cómo se Guarda tu Secreto? (Amigable)

```mermaid
flowchart LR
    A[Sal 16B - Sello de Seguridad] --> B[Nonce 12B - Número Aleatorio]
    B --> C[Cifrado - Secreto Cifrado]
    C --> D[Tag 16B - Etiqueta de Verificación]
```

## Flujo de Cifrado (Técnico) / Proceso de Guardado (Amigable)

```mermaid
sequenceDiagram
    participant T as Tú (Usuario)
    participant A as Aplicación (App)
    participant C as CAOS
    participant P as PBKDF2 (Mezclador)
    participant G as GCM (Guardián)
    
    T->>A: Escribes tu mensaje
    A->>C: encrypt - Guardar mensaje
    C->>C: Gen sal - Crear sello especial
    C->>P: Deriva clave - Mezclar contraseña
    P-->>C: Clave - Llave maestra
    C->>C: Gen nonce - Crear número aleatorio
    C->>G: Cifra - Proteger mensaje
    G-->>C: Cifrado+Tag - Mensaje protegido
    C->>C: Compone - Empaquetar todo
    C-->>A: Resultado - Mensaje seguro
    A-->>T: Cifrado - ¡Listo!
```

## Flujo de Descifrado (Técnico) / Proceso de Lectura (Amigable)

```mermaid
sequenceDiagram
    participant T as Tú (Usuario)
    participant A as Aplicación (App)
    participant C as CAOS
    participant P as PBKDF2 (Mezclador)
    participant G as GCM (Guardián)
    
    T->>A: Quieres leer tu mensaje
    A->>C: decrypt - Abrir mensaje
    C->>C: Extrae sal - Verificar sello
    C->>P: Deriva clave - Mezclar contraseña
    P-->>C: Clave - Llave maestra
    C->>C: Extrae nonce - Extraer número aleatorio
    C->>C: Extrae datos - Extraer mensaje
    C->>G: Descifra - Verificar y abrir
    G-->>C: Original - Mensaje original
    C-->>A: Resultado - Tu mensaje
    A-->>T: Mensaje - ¡Aquí está!
```

## Comparación de Sistemas (Técnico y Amigable)

```mermaid
flowchart TD
    subgraph "AES-CBC - Sistema Básico"
        A1[Contraseña] --> B1[Hash - Llave Simple]
        B1 --> C1[Clave]
        D1[Datos] --> E1[CBC - Caja Básica]
        C1 --> E1
        F1[IV - Número] --> E1
        E1 --> H1[Sin Auth - Sin Verificación]
    end
    
    subgraph "CAOS V4"
        A2[Contraseña] --> B2[PBKDF2 - Mezclador Seguro]
        B2 --> C2[Clave - Llave Maestra]
        D2[Datos] --> E2[GCM - Caja Fuerte Digital]
        C2 --> E2
        F2[Nonce - Número Aleatorio] --> E2
        E2 --> G2[Auth - Con Verificación]
    end
```

## Seguridad vs Rendimiento (Técnico) / Seguridad y Velocidad (Amigable)

| Algoritmo (Técnico) | Sistema (Amigable) | Rendimiento/Velocidad | Seguridad | Posición/Recomendación |
|---------------------|-------------------|----------------------|-----------|------------------------|
| DES | Sistema Antiguo | Muy bajo/Lenta | Muy baja | Obsoleto/No usar |
| 3DES | Sistema Antiguo Mejorado | Bajo/Lenta | Baja | Obsoleto/No usar |
| AES-ECB | Sistema Básico Simple | Alto/Rápida | Baja | No recomendado/Para cosas simples |
| AES-CBC | Sistema Básico | Alto/Rápida | Media | Básico/Para cosas simples |
| RSA | Sistema Complejo | Bajo/Lenta | Alta | Específico/Para cosas muy importantes |
| CBC+HMAC | Sistema Seguro | Medio/Rápida | Alta | Recomendado/Para la mayoría de usos |
| Híbrido | Sistema Mixto | Medio/Rápida | Alta | Específico/Para usos especiales |
| CAOS V3 | Sistema Avanzado | Alto/Muy Rápida | Alta | Recomendado/Para la mayoría de usos |
| CAOS V4 | Sistema Óptimo | Alto/Muy Rápida | Muy alta | Óptimo/Para todo tipo de secretos |

## Componentes (Técnico) / Partes Principales (Amigable)

```mermaid
classDiagram
    class CAOS {
        +encrypt - guardar_mensaje()
        +decrypt - leer_mensaje()
    }
    
    class PBKDF2 {
        +derive - crear_llave()
    }
    
    class GCM {
        +encrypt - proteger()
        +decrypt - verificar()
    }
    
    CAOS --> PBKDF2
    CAOS --> GCM
```

## Tiempos de Operación (Técnico) / ¿Cuánto Tarda? (Amigable)

```mermaid
gantt
    title Tiempos de Operación - Tiempo de Protección
    dateFormat X
    axisFormat %s
    
    section CBC - Sistema Básico
    100B - Mensaje Corto  : 0, 1
    1KB - Mensaje Medio   : 0, 2
    10KB - Mensaje Largo  : 0, 5
    
    section RSA - Sistema Complejo
    100B - Mensaje Corto  : 0, 20
    1KB - Mensaje Medio   : 0, 80
    10KB - Mensaje Largo  : 0, 500
    
    section CAOS V4
    100B - Mensaje Corto  : 0, 15
    1KB - Mensaje Medio   : 0, 25
    10KB - Mensaje Largo  : 0, 40
```

Estos diagramas muestran la arquitectura completa de CAOS V4, incluyendo su estructura de capas, flujos de operación y ventajas comparativas, presentados tanto en términos técnicos como en un lenguaje más amigable para facilitar la comprensión. 