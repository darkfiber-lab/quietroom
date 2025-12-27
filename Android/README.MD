# QuietRoom Android Chat Client

## Overview

This is an Android implementation of the QuietRoom secure chat client, ported from the original Go CLI version. It maintains core features like end-to-end encryption, Diffie-Hellman key exchange, traffic obfuscation, decoy traffic, and file transfers. The CLI interface is replaced with a simple Android GUI using Kotlin, featuring a message display, input field, send button, and file send button.

The Go logic is packaged as a bindable library using `gomobile` and integrated into an Android app. This ensures cross-platform compatibility while leveraging Android's UI capabilities.

### Key Features
- **Secure Connection**: TLS with certificate pinning, RSA authentication, and AES-GCM encryption.
- **Diffie-Hellman Key Exchange**: For perfect forward secrecy.
- **Traffic Obfuscation**: Padded packets to hide message types.
- **Decoy Traffic**: Optional background noise to mask activity.
- **File Transfers**: Send/receive files with progress tracking and SHA-256 hash verification.
- **Themed Messages**: Color-coded output parsed via Spannable in Android.
- **Notifications**: Sound alerts for incoming messages.
- **Offline-First**: Local config and public key loading.

### Requirements
- Go 1.20+ with `gomobile` installed (`go install golang.org/x/mobile/cmd/gomobile@latest`).
- Android Studio with Kotlin support.
- Android SDK 21+ (minSdk).
- Permissions: Internet, Storage (read/write external).
- Files: `chat_public.pem` and `client_config.json` (place in app's files dir or assets).

## Build Instructions

### 1. Build the Go Library
Create a directory `chat` and place the Go code in `chat.go`.

Run:

gomobile bind -target=android -o=chat.aar ./chat

This generates `chat.aar` for Android integration.

### 2. Set Up Android Project
- Create a new Android Studio project.
- Copy `chat.aar` to `app/libs`.
- In `app/build.gradle`, add:
 
 dependencies {
      implementation files('libs/chat.aar')
  }

- Sync the project.

### 3. Add Code
- Replace `app/build.gradle` with the provided content.
- Update `AndroidManifest.xml` with the provided XML.
- Create `activity_main.xml` in `res/layout`.
- Create `MainActivity.kt` in `src/main/kotlin/com/example/quietroom`.

### 4. Run the App
- Build and run in Android Studio.
- Copy `chat_public.pem` and `client_config.json` to the device's storage (e.g., via ADB) and adjust Go paths if needed.

## Code Details

### Go Package (`chat/chat.go`)
This is the core logic, bindable to Android. (Full code omitted for brevity; refer to the original implementation for details.)

Key exported functions:
- `NewClient()`: Creates a new client instance.
- `Connect(serverAddr string)`: Establishes a secure connection.
- `Send(text string)`: Sends a message or command.
- `SendFile(filePath string)`: Sends a file.
- `Receive() chan string`: Channel for incoming messages.
- `Close()`: Closes the connection.

### Android `build.gradle` (app)
```groovy
plugins {
  id 'com.android.application'
  id 'org.jetbrains.kotlin.android'
}

android {
  namespace 'com.example.quietroom'
  compileSdk 34

  defaultConfig {
      applicationId "com.example.quietroom"
      minSdk 21
      targetSdk 34
      versionCode 1
      versionName "1.0"

      testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
  }

  buildTypes {
      release {
          minifyEnabled false
          proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
      }
  }
  compileOptions {
      sourceCompatibility JavaVersion.VERSION_1_8
      targetCompatibility JavaVersion.VERSION_1_8
  }
  kotlinOptions {
      jvmTarget = '1.8'
  }
}

dependencies {
  implementation 'androidx.core:core-ktx:1.13.1'
  implementation 'androidx.appcompat:appcompat:1.7.0'
  implementation 'com.google.android.material:material:1.12.0'
  implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
  implementation 'androidx.activity:activity-ktx:1.9.2'
  implementation 'androidx.fragment:fragment-ktx:1.8.4'
  implementation files('libs/chat.aar')
  testImplementation 'junit:junit:4.13.2'
  androidTestImplementation 'androidx.test.ext:junit:1.2.1'
  androidTestImplementation 'androidx.test.espresso:espresso-core:3.6.1'
}
