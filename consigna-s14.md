# Evaluación Técnica: Análisis y Mejora de Seguridad en Aplicación Android

## Introducción

Esta evaluación técnica se basa en una aplicación Android que implementa un sistema de demostración de permisos y protección de datos. La aplicación utiliza tecnologías modernas como Kotlin, Android Security Crypto, SQLCipher y patrones de arquitectura MVVM.

---

## Parte 1: Análisis de Seguridad Básico (0-7 puntos)

### 1.1 Identificación de Vulnerabilidades (2 puntos)

Analiza el archivo `DataProtectionManager.kt` y responde:

- **¿Qué método de encriptación se utiliza para proteger datos sensibles?**

  Se usa `EncryptedSharedPreferences` con:
  - Clave maestra (MasterKey) usando el esquema `AES256_GCM`.
  - Encriptación de llaves con `AES256_SIV`.
  - Encriptación de valores con `AES256_GCM`.

- **Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging**

  1. **Uso incorrecto de separadores de línea en logs**  
     En el código, para separar líneas se usa la cadena literal `"\\n"` (doble barra invertida + n), que en realidad guarda el texto `\n` en lugar de un salto de línea real.  
     ```kotlin
     val newLogs = if (existingLogs.isEmpty()) {
         logEntry
     } else {
         "$existingLogs\\n$logEntry"
     }
     ```

  2. **Posible crecimiento indefinido y problemas de concurrencia**  
     Cada vez que se agrega un log, se lee todo el historial, se agrega una línea y se vuelve a escribir todo. Esto puede causar:  
     - Crecimiento innecesario del almacenamiento (degradación de performance).  
     - Condiciones de carrera si múltiples hilos acceden simultáneamente, provocando pérdida o corrupción de logs.

- **¿Qué sucede si falla la inicialización del sistema de encriptación?**

  Los datos sensibles **no estarán encriptados**, quedando almacenados en texto plano. Se pierde la protección de confidencialidad para esos datos, aumentando el riesgo ante accesos no autorizados.

---

### 1.2 Permisos y Manifiesto (2 puntos)

Examina `AndroidManifest.xml` y `MainActivity.kt`:

- **Lista todos los permisos peligrosos declarados en el manifiesto**

  1. Cámara (`android.permission.CAMERA`)  
  2. Leer almacenamiento externo (`android.permission.READ_EXTERNAL_STORAGE`)  
  3. Leer imágenes (`android.permission.READ_MEDIA_IMAGES`)  
  4. Grabar audio (`android.permission.RECORD_AUDIO`)  
  5. Leer contactos (`android.permission.READ_CONTACTS`)  
  6. Realizar llamadas telefónicas (`android.permission.CALL_PHONE`)  
  7. Enviar SMS (`android.permission.SEND_SMS`)  
  8. Acceso a ubicación aproximada (`android.permission.ACCESS_COARSE_LOCATION`)

- **¿Qué patrón se utiliza para solicitar permisos en runtime?**

  Se usa un método moderno llamado **Activity Result API**, con `registerForActivityResult`.  
  Cuando el usuario toca un permiso, la app lo solicita, y al responder (aceptar o negar), la app recibe esa respuesta y actúa en consecuencia.

- **Identifica qué configuración de seguridad previene backups automáticos**

  En la etiqueta `<application>` está:  
  ```xml
  android:allowBackup="false"
Esto impide que Android haga un respaldo automático de los datos de la app, ayudando a proteger información sensible.
### 1.3 Gestión de Archivos (3 puntos)

Revisa `CameraActivity.kt` y `file_paths.xml`:

- **¿Cómo se implementa la compartición segura de archivos de imágenes?**

  Se usa un `FileProvider` que genera un URI con permisos temporales para compartir archivos. Esto permite que otras apps (como la cámara) puedan acceder a los archivos sin exponer rutas directas ni dar permisos permanentes.  
  En el código, al crear la foto, se genera un URI con `FileProvider.getUriForFile()`, y ese URI se usa para tomar la foto y mostrarla.

- **¿Qué autoridad se utiliza para el FileProvider?**

  La autoridad usada es:  com.example.seguridad_priv_a.fileprovider
Esta se declara en el manifiesto y luego se usa en el código para generar URIs seguros.

- **Explica por qué no se debe usar `file://` URIs directamente**

- Porque los URIs con esquema `file://` exponen la ruta exacta del archivo.  
- No otorgan permisos seguros a otras aplicaciones.  
- En Android 7+ generan errores debido a restricciones de seguridad.  
- `FileProvider` crea URIs con permisos temporales que protegen la privacidad y seguridad del archivo.

## Parte 2: Implementación y Mejoras Intermedias (8-14 puntos)

### 2.1 Fortalecimiento de la Encriptación (3 puntos)
Modifica `DataProtectionManager.kt` para implementar:

- Rotación automática de claves maestras cada 30 días
**Descripción:**
Cada 30 días se fuerza la rotación de la clave maestra utilizada por `EncryptedSharedPreferences`. Se almacena la última fecha de rotación en el mismo archivo seguro.

**Código relevante:**

```kotlin
private fun shouldRotateKey(): Boolean {
    val lastRotation = securePrefs.getLong("last_rotation", 0L)
    val currentTime = System.currentTimeMillis()
    return (currentTime - lastRotation) > TimeUnit.DAYS.toMillis(30)
}

private fun rotateEncryptionKey() {
    if (shouldRotateKey()) {
        securePrefs.edit().putLong("last_rotation", System.currentTimeMillis()).apply()
        Log.d("Security", "Encryption key rotated.")
    }
}
```
- Verificación de integridad de datos encriptados usando HMAC
```kotlin
fun saveSecureData(key: String, value: String, userId: String) {
    val hmac = generateHMAC(value, userId)
    securePrefs.edit()
        .putString(key, value)
        .putString("${key}_hmac", hmac)
        .apply()
}

fun verifyDataIntegrity(key: String): Boolean {
    val value = securePrefs.getString(key, null) ?: return false
    val storedHmac = securePrefs.getString("${key}_hmac", null) ?: return false
    val userId = securePrefs.getString("user_id", "default_user") ?: "default_user"
    val computedHmac = generateHMAC(value, userId)
    return storedHmac == computedHmac
}
```
- Implementación de key derivation con salt único por usuario
```kotlin
private fun generateHMAC(data: String, userId: String): String {
    val salt = userId.toByteArray(StandardCharsets.UTF_8)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val spec = PBEKeySpec(userId.toCharArray(), salt, 10000, 256)
    val secret = factory.generateSecret(spec).encoded
    val hmacKey = SecretKeySpec(secret, "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(hmacKey)
    val result = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
    return Base64.encodeToString(result, Base64.NO_WRAP)
}
```
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

1. SecurityAuditManager.kt

Clase personalizada encargada de:

⚡ Detección de accesos sospechosos: identifica intentos múltiples en corto tiempo por ID de permiso.

⛔ Rate limiting: bloquea acciones cuando hay muchos accesos seguidos (por defecto más de 3 intentos en 10 segundos).

🚨 Generación de alertas: muestra un AlertDialog si se detectan patrones anómalos.

📃 Exportación de logs firmados: exporta un archivo .json con los eventos registrados, firmado digitalmente con HMAC-SHA256.
```kotlin
val securityAuditManager = SecurityAuditManager.getInstance(context)
val allowed = securityAuditManager.registerAccess("Camera")
if (allowed) {
    startActivity(Intent(context, CameraActivity::class.java))
} else {
    // Bloqueado por actividad sospechosa
}
```
📂 Estructura del Proyecto
```kotlin
com.example.seguridad_priv_a
|├── data/
|   ├── DataProtectionManager.kt
|   ├── PermissionItem.kt
|   └── SecurityAuditManager.kt   ← Nueva clase implementada
|
|├── adapter/
|   └── PermissionsAdapter.kt
|
|├── MainActivity.kt               ← Integración con SecurityAuditManager
|├── CameraActivity.kt
|├── CalendarActivity.kt
|├── MicrophoneActivity.kt
|└── StorageActivity.kt
```
### 2.3 Biometría y Autenticación (3 puntos)
Implementa autenticación biométrica en `DataProtectionActivity.kt`:
- Integra BiometricPrompt API para proteger el acceso a logs
- Implementa fallback a PIN/Pattern si biometría no está disponible
- Añade timeout de sesión tras inactividad de 5 minutos
#### 🔐 1. Autenticación Biométrica (Huella, Rostro, etc.)
Se ha integrado la API `BiometricPrompt` de Android para permitir el acceso a la actividad **solo mediante autenticación biométrica válida**.

- Al iniciar la actividad, se muestra un cuadro de diálogo biométrico al usuario.
- Si el usuario cancela o falla la autenticación, no puede acceder a los datos sensibles.
- La autenticación se vuelve a solicitar si la app es reabierta tras tiempo de inactividad.

#### 🔁 2. Mecanismo de Respaldo (Fallback)
Si el dispositivo **no cuenta con sensores biométricos** o el usuario no tiene una biometría configurada, se usa un **fallback manual**, actualmente simulado como un diálogo personalizado que permite ingresar un código de respaldo (PIN o patrón simulado).

> 📌 Este fallback puede conectarse con almacenamiento cifrado o autenticación real basada en contraseña en futuras versiones.

#### ⏳ 3. Expiración de Sesión (Inactividad > 5 min)
Se implementó un sistema de control de sesión que:
- Guarda la hora del último uso mediante `EncryptedSharedPreferences`.
- Al volver a abrir la actividad, se compara la hora actual con la última actividad.
- Si han pasado más de **5 minutos de inactividad**, se solicita **reautenticación**.

---
### 📁 Archivos Relevantes

- `DataProtectionActivity.kt`: Lógica de autenticación biométrica y verificación de sesión.
- `DataProtectionManager.kt`: Clase encargada del almacenamiento seguro y auditoría.
- `res/xml/biometric_prompt.xml`: (opcional) Configuración visual del prompt.
- `AndroidManifest.xml`: Incluye permisos y declaración de la actividad protegida.

---
```kotlin
private fun setupBiometricAuthentication() {
    val executor = ContextCompat.getMainExecutor(this)

    biometricPrompt = BiometricPrompt(this, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Toast.makeText(applicationContext, "Autenticación exitosa", Toast.LENGTH_SHORT).show()
                // Permitir acceso a los datos protegidos
                lastInteractionTime = System.currentTimeMillis()
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Toast.makeText(applicationContext, "Autenticación fallida", Toast.LENGTH_SHORT).show()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Toast.makeText(applicationContext, "Error: $errString", Toast.LENGTH_SHORT).show()
            }
        })

    promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Autenticación Requerida")
        .setSubtitle("Usa tu huella o patrón para continuar")
        .setDeviceCredentialAllowed(true) // Permite PIN/Patrón como fallback
        .build()
}
```
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
# 3.2 - Seguridad en Android: Protección de Datos y Permisos

## 📱 Descripción General

Este proyecto Android en Kotlin implementa mecanismos de seguridad enfocados en la **protección de datos sensibles** y el **control de permisos**, utilizando prácticas modernas como `EncryptedSharedPreferences`, detección de debugging, cifrado HMAC, derivación de claves con `PBKDF2`, y políticas de permisos explícitas.

## ✅ Funcionalidades Implementadas

### 🔐 Protección de Datos
- Uso de `EncryptedSharedPreferences` para guardar datos sensibles cifrados.
- Generación de claves maestras mediante `MasterKey`.
- Implementación de rotación automática de claves cada 30 días.
- Integridad verificada con HMAC (SHA-256).
- Derivación de claves personalizadas con salt por usuario usando PBKDF2.

### 🛡️ Seguridad Avanzada
- Detección de debugging (modo desarrollador) para cerrar la app si se detecta.
- Ofuscación de strings sensibles.
- Uso de ProGuard/R8 para minimizar y ofuscar código en versiones `release`.

### 🔧 Permisos Sensibles
- Actividades individuales para cada permiso:
  - Cámara (`CameraActivity`)
  - Micrófono (`MicrophoneActivity`)
  - Calendario (`CalendarActivity`)
  - Almacenamiento (`StorageActivity`)
- Solicitud dinámica de permisos sensibles.
- Iconos personalizados e interfaz simple para usuarios.

## 📂 Estructura del Proyecto

├── app/
│ ├── java/com/example/seguridad_priv_a/
│ │ ├── MainActivity.kt
│ │ ├── CameraActivity.kt
│ │ ├── MicrophoneActivity.kt
│ │ ├── CalendarActivity.kt
│ │ ├── StorageActivity.kt
│ │ ├── PermissionsApplication.kt
│ │ ├── data/
│ │ │ ├── DataProtectionManager.kt
│ │ │ └── PermissionItem.kt
│ │ └── adapter/
│ │ └── PermissionsAdapter.kt
│ └── res/
│ ├── layout/
│ ├── values/
│ └── xml/

## ⚙️ Configuración de ProGuard (build.gradle)

```groovy
buildTypes {
    release {
        minifyEnabled true
        shrinkResources true
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
    }
}
```
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
