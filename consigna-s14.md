# Evaluación Técnica: Análisis y Mejora de Seguridad en Aplicación Android

## Introducción
Esta evaluación técnica se basa en una aplicación Android que implementa un sistema de demostración de permisos y protección de datos. La aplicación utiliza tecnologías modernas como Kotlin, Android Security Crypto, SQLCipher y patrones de arquitectura MVVM.

## Parte 1: Análisis de Seguridad Básico (0-7 puntos)

### 1.1 Identificación de Vulnerabilidades (2 puntos)
Analiza el archivo `DataProtectionManager.kt` y responde:
- ¿Qué método de encriptación se utiliza para proteger datos sensibles?

Se usa EncryptedSharedPreferences con:
Clave maestra (MasterKey) usando el esquema AES256_GCM.
Encriptación de llaves con AES256_SIV.
Encriptación de valores con AES256_GCM.
  
- Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging
  
1.- Vulnerabilidad 1:
Uso incorrecto de separadores de línea en logs
En el código, para separar líneas se usa la cadena literal "\\n" (doble barra invertida + n), que en realidad guarda el texto \n en lugar de un salto de línea real.
val newLogs = if (existingLogs.isEmpty()) {
    logEntry
} else {
    "$existingLogs\\n$logEntry"
}

2.- Vulnerabilidad 2:
Posible crecimiento indefinido y problemas de concurrencia
Cada vez que se agrega un log, se lee todo el historial, se agrega una línea y se vuelve a escribir todo.
Esto puede causar:
Crecimiento innecesario del almacenamiento (performance degradada).
Condiciones de carrera si múltiples hilos o procesos acceden simultáneamente, causando pérdida o corrupción de logs.

- ¿Qué sucede si falla la inicialización del sistema de encriptación?
  
Los datos sensibles NO estarán encriptados, quedando almacenados en texto plano.
Se pierde la protección de confidencialidad para esos datos, aumentando el riesgo ante accesos no autorizados.

### 1.2 Permisos y Manifiesto (2 puntos)
Examina `AndroidManifest.xml` y `MainActivity.kt`:
- Lista todos los permisos peligrosos declarados en el manifiesto
  
1.- Cámara (android.permission.CAMERA)
2.- Leer almacenamiento externo (android.permission.READ_EXTERNAL_STORAGE)
3.- Leer imágenes (android.permission.READ_MEDIA_IMAGES)
4.- Grabar audio (android.permission.RECORD_AUDIO)
5.- Leer contactos (android.permission.READ_CONTACTS)
6.- Llamar por teléfono (android.permission.CALL_PHONE)
7.- Enviar SMS (android.permission.SEND_SMS)
8.- Acceso a ubicación aproximada (android.permission.ACCESS_COARSE_LOCATION)

- ¿Qué patrón se utiliza para solicitar permisos en runtime?

Se usa un método moderno que se llama Activity Result API, con registerForActivityResult. Básicamente, cuando el usuario toca un permiso, la app pide ese permiso, y cuando el usuario responde (lo acepta o lo niega), la app recibe esa respuesta y actúa según sea el caso.

- Identifica qué configuración de seguridad previene backups automáticos

En la etiqueta <application>, está esto:
android:allowBackup="false"
Eso hace que Android no permita que se haga un respaldo automático de los datos de la app, lo que ayuda a proteger información sensible.

### 1.3 Gestión de Archivos (3 puntos)
Revisa `CameraActivity.kt` y `file_paths.xml`:
- ¿Cómo se implementa la compartición segura de archivos de imágenes?
  
Se usa un FileProvider que genera un URI con permisos temporales para compartir archivos. Esto permite que otras apps (por ejemplo, la cámara) puedan acceder a los archivos sin exponer rutas de archivos directas ni dar permisos permanentes. En el código, cuando se crea la foto, se genera un URI con FileProvider.getUriForFile(), y ese URI se usa para tomar la foto y mostrarla.

- ¿Qué autoridad se utiliza para el FileProvider?
  
La autoridad usada es "com.example.seguridad_priv_a.fileprovider", que se declara en el manifiesto y es usada luego en el código para generar los URIs seguros.

- Explica por qué no se debe usar `file://` URIs directamente
  
Porque los URIs con esquema file:// exponen la ruta exacta del archivo y no otorgan permisos seguros a otras apps. Esto puede causar errores en Android (especialmente desde Android 7+) y problemas de seguridad, porque no se controla quién accede al archivo. En cambio, el FileProvider crea un URI con permisos temporales que protege la privacidad y seguridad de los archivos.

## Parte 2: Implementación y Mejoras Intermedias (8-14 puntos)

### 2.1 Fortalecimiento de la Encriptación (3 puntos)
Modifica `DataProtectionManager.kt` para implementar:
- Rotación automática de claves maestras cada 30 días
- Verificación de integridad de datos encriptados usando HMAC
- Implementación de key derivation con salt único por usuario

```kotlin
// Ejemplo de estructura esperada
fun rotateEncryptionKey(): Boolean {
    // Tu implementación aquí
}

fun verifyDataIntegrity(key: String): Boolean {
    // Tu implementación aquí
}
```

### 2.2 Sistema de Auditoría Avanzado (3 puntos)
Crea una nueva clase `SecurityAuditManager` que:
- Detecte intentos de acceso sospechosos (múltiples solicitudes en corto tiempo)
- Implemente rate limiting para operaciones sensibles
- Genere alertas cuando se detecten patrones anómalos
- Exporte logs en formato JSON firmado digitalmente

### 2.3 Biometría y Autenticación (3 puntos)
Implementa autenticación biométrica en `DataProtectionActivity.kt`:
- Integra BiometricPrompt API para proteger el acceso a logs
- Implementa fallback a PIN/Pattern si biometría no está disponible
- Añade timeout de sesión tras inactividad de 5 minutos

## Parte 3: Arquitectura de Seguridad Avanzada (15-20 puntos)

### 3.1 Implementación de Zero-Trust Architecture (3 puntos)
Diseña e implementa un sistema que:
- Valide cada operación sensible independientemente
- Implemente principio de menor privilegio por contexto
- Mantenga sesiones de seguridad con tokens temporales
- Incluya attestation de integridad de la aplicación

### 3.2 Protección Contra Ingeniería Inversa (3 puntos)
Implementa medidas anti-tampering:
- Detección de debugging activo y emuladores
- Obfuscación de strings sensibles y constantes criptográficas
- Verificación de firma digital de la aplicación en runtime
- Implementación de certificate pinning para comunicaciones futuras

### 3.3 Framework de Anonimización Avanzado (2 puntos)
Mejora el método `anonymizeData()` actual implementando:
- Algoritmos de k-anonimity y l-diversity
- Differential privacy para datos numéricos
- Técnicas de data masking específicas por tipo de dato
- Sistema de políticas de retención configurables

```kotlin
class AdvancedAnonymizer {
    fun anonymizeWithKAnonymity(data: List<PersonalData>, k: Int): List<AnonymizedData>
    fun applyDifferentialPrivacy(data: NumericData, epsilon: Double): NumericData
    fun maskByDataType(data: Any, maskingPolicy: MaskingPolicy): Any
}
```

### 3.4 Análisis Forense y Compliance (2 puntos)
Desarrolla un sistema de análisis forense que:
- Mantenga chain of custody para evidencias digitales
- Implemente logs tamper-evident usando blockchain local
- Genere reportes de compliance GDPR/CCPA automáticos
- Incluya herramientas de investigación de incidentes

## Criterios de Evaluación

### Puntuación Base (0-7 puntos):
- Correcta identificación de vulnerabilidades y patrones de seguridad
- Comprensión de conceptos básicos de Android Security
- Documentación clara de hallazgos

### Puntuación Intermedia (8-14 puntos):
- Implementación funcional de mejoras de seguridad
- Código limpio siguiendo principios SOLID
- Manejo adecuado de excepciones y edge cases
- Pruebas unitarias para componentes críticos

### Puntuación Avanzada (15-20 puntos):
- Arquitectura robusta y escalable
- Implementación de patrones de seguridad industry-standard
- Consideración de amenazas emergentes y mitigaciones
- Documentación técnica completa con diagramas de arquitectura
- Análisis de rendimiento y optimización de operaciones criptográficas

## Entregables Requeridos

1. **Código fuente** de todas las implementaciones solicitadas
2. **Informe técnico** detallando vulnerabilidades encontradas y soluciones aplicadas
3. **Diagramas de arquitectura** para componentes de seguridad nuevos
4. **Suite de pruebas** automatizadas para validar medidas de seguridad
5. **Manual de deployment** con consideraciones de seguridad para producción

## Tiempo Estimado
- Parte 1: 2-3 horas
- Parte 2: 4-6 horas  
- Parte 3: 8-12 horas

## Recursos Permitidos
- Documentación oficial de Android
- OWASP Mobile Security Guidelines
- Libraries de seguridad open source
- Stack Overflow y comunidades técnicas

---

**Nota**: Esta evaluación requiere conocimientos sólidos en seguridad móvil, criptografía aplicada y arquitecturas Android modernas. Se valorará especialmente la capacidad de aplicar principios de security-by-design y el pensamiento crítico en la identificación de vectores de ataque.
