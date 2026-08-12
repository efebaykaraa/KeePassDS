# KeePassDS

**KeePassDS means “KeePass Droid Synced.”** It is a KeePassDX-based Android password manager with authenticated local-network synchronization for KeePassXCS.

KeePassDS reads and writes standard KeePass KDBX databases. Passwords stay protected by the database master key; synchronization transfers the already encrypted KDBX file over the local network.

## LAN synchronization

- Discovers KeePassXCS and KeePassDS devices on the same Wi-Fi network.
- Pairs once using accept/decline confirmation and a six-digit verification code.
- Stores the peer secret in encrypted KDBX custom data.
- Synchronizes later saves without asking for confirmation again.
- Merges peer changes using KeePass database history and deletion rules.
- Verifies the previous hash immediately before replacement and restores the old file after an incomplete local transaction.

Open and unlock the same database on both devices. In KeePassDS open the database menu and select `LAN synchronization`. Choose the device and confirm the current password database. Accept on the other device, then enter its six-digit code.

KeePassDS listens for sync requests while its database screen is open and unlocked. Guest Wi-Fi or client-isolation settings can prevent discovery.

## Build and install

Build the libre debug APK with JDK 21 and the Android SDK:

```bash
./gradlew :app:assembleLibreDebug
```

Install it with ADB:

```bash
adb install -r app/build/outputs/apk/libre/debug/app-libre-debug.apk
```

Important implementation paths:

- `app/src/main/java/com/kunzisoft/keepass/lansync/` — discovery, pairing and synchronization
- `app/src/test/java/com/kunzisoft/keepass/lansync/` — cross-platform protocol tests
- `database/src/main/java/com/kunzisoft/keepass/database/element/Database.kt` — KDBX custom-data access

## Upstream and license

KeePassDS is based on [KeePassDX](https://github.com/Kunzisoft/KeePassDX). It retains the upstream GPLv3 licensing; see `LICENSE` for details.
