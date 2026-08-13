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

To copy a database to a new phone, open and unlock it in KeePassXCS. On the KeePassDS start screen, tap `LAN devices / Retrieve from KeePassXCS`, choose the computer, then choose the open database. Accept the request in KeePassXCS, enter the displayed six-digit code on the phone, and choose where Android should save the downloaded `.kdbx` file. Open it with its normal master password. The pairing is stored after the first unlock; later saves synchronize without another prompt.

You can also initiate the transfer from the computer. Leave KeePassDS on its start screen, then in KeePassXCS choose `Database → Remote Sync → Pair or Send Database to LAN Device`. Select the phone and database. Accept the incoming database on the phone, enter the phone's six-digit code on the computer, then choose the Android save location. Both device selectors offer `Search again`, similar to rescanning for Bluetooth devices.

For a database that is already present on both devices, open it in KeePassDS and use `LAN synchronization` from the database menu to pair it directly.

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
