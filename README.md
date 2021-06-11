**Full disk encryption**

## Installation

For **OpenOS**, just run this command:

```
wget -f https://raw.githubusercontent.com/BrightYC/Catch/main/catch.lua /bin/catch.lua
```

For **MineOS** you can download an app called 'Catch' in the App Market.

## Usage

Within OpenOS, you can encrypt different drives, like to be portable.

Examples:

* catch --encrypt --drive=XXX (Drive XXX will be encrypted)
* catch --encrypt (Relative directory will be encrypted - if it's drive in /mnt/xxx, then it will encrypt drive xxx, otherwise if we are staying in the root directory - root directory will be encrypted)
* catch --decrypt --drive=XXX

In MineOS, you can only encrypt the root directory. If you'll try to open init.lua on an encrypted drive - it will asks for a passphrase, and on success drive can be found in `/Mounts/Catch-XXX`.
If you run init.lua with argument `rootfs`, it will run root filesystem encrypting app.

## Iter-time
Iter times defines KDF iterations, that means if the number are high - the drive will be harder to crack. But if iteration count are too high - deriving key will be too slow. Default value is `5000`.
