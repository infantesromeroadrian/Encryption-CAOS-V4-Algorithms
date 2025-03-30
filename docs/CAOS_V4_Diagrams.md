# Diagramas de Arquitectura CAOS V4

A continuación se presentan los diagramas que ilustran la arquitectura del algoritmo CAOS V4.

## Arquitectura de Tres Capas

```mermaid
flowchart TD
    subgraph "Capa 1: Derivación"
        A[Contraseña] --> B[Sal]
        B --> C[PBKDF2]
        C --> D[Clave AES]
    end
    
    subgraph "Capa 2: Cifrado"
        E[Datos] --> F[AES-GCM]
        D --> F
        G[Nonce] --> F
        F --> H[Cifrado+Tag]
    end
    
    subgraph "Capa 3: Transporte"
        B --> I[Metadatos]
        G --> I
        H --> I
        I --> J[Mensaje]
    end
```

## Estructura del Mensaje

```mermaid
flowchart LR
    A[Sal 16B] --> B[Nonce 12B]
    B --> C[Cifrado]
    C --> D[Tag 16B]
```

## Flujo de Cifrado

```mermaid
sequenceDiagram
    participant U as Usuario
    participant A as App
    participant C as CAOS
    participant P as PBKDF2
    participant G as GCM
    
    U->>A: Mensaje
    A->>C: encrypt()
    C->>C: Gen sal
    C->>P: Deriva clave
    P-->>C: Clave
    C->>C: Gen nonce
    C->>G: Cifra
    G-->>C: Cifrado+Tag
    C->>C: Compone
    C-->>A: Resultado
    A-->>U: Cifrado
```

## Flujo de Descifrado

```mermaid
sequenceDiagram
    participant U as Usuario
    participant A as App
    participant C as CAOS
    participant P as PBKDF2
    participant G as GCM
    
    U->>A: Cifrado
    A->>C: decrypt()
    C->>C: Extrae sal
    C->>P: Deriva clave
    P-->>C: Clave
    C->>C: Extrae nonce
    C->>C: Extrae datos
    C->>G: Descifra
    G-->>C: Original
    C-->>A: Resultado
    A-->>U: Mensaje
```

## Comparación

```mermaid
flowchart TD
    subgraph "AES-CBC"
        A1[Contraseña] --> B1[Hash]
        B1 --> C1[Clave]
        D1[Datos] --> E1[CBC]
        C1 --> E1
        F1[IV] --> E1
        E1 --> H1[Sin Auth]
    end
    
    subgraph "CAOS V4"
        A2[Contraseña] --> B2[PBKDF2]
        B2 --> C2[Clave]
        D2[Datos] --> E2[GCM]
        C2 --> E2
        F2[Nonce] --> E2
        E2 --> H2[Auth]
    end
```

## Seguridad vs Rendimiento

| Algoritmo | Rendimiento | Seguridad | Posición |
|-----------|-------------|-----------|----------|
| DES       | Muy bajo    | Muy baja  | Obsoleto |
| 3DES      | Bajo        | Baja      | Obsoleto |
| AES-ECB   | Alto        | Baja      | No recomendado |
| AES-CBC   | Alto        | Media     | Básico |
| RSA       | Bajo        | Alta      | Específico |
| CBC+HMAC  | Medio       | Alta      | Recomendado |
| Híbrido   | Medio       | Alta      | Específico |
| CAOS V3   | Alto        | Alta      | Recomendado |
| CAOS V4   | Alto        | Muy alta  | Óptimo |

## Componentes

```mermaid
classDiagram
    class CAOS {
        +encrypt()
        +decrypt()
    }
    
    class PBKDF2 {
        +derive()
    }
    
    class GCM {
        +encrypt()
        +decrypt()
    }
    
    CAOS --> PBKDF2
    CAOS --> GCM
```

## Tiempos de Operación

```mermaid
gantt
    title Tiempos
    dateFormat X
    axisFormat %s
    
    section CBC
    100B  : 0, 1
    1KB   : 0, 2
    10KB  : 0, 5
    
    section RSA
    100B  : 0, 20
    1KB   : 0, 80
    10KB  : 0, 500
    
    section Híbrido
    100B  : 0, 25
    1KB   : 0, 35
    10KB  : 0, 60
    
    section CAOS V4
    100B  : 0, 15
    1KB   : 0, 25
    10KB  : 0, 40
```

Estos diagramas muestran la arquitectura completa de CAOS V4, incluyendo su estructura de capas, flujos de operación y ventajas comparativas. 