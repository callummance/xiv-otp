# xiv-otp
OTP generator for lazy Linux+XIVLauncher users

## How it works
This tool uses the freedesktop secret service API to store the OTP secret for your Square Enix account. It can then use that secret to generate an OTP token and send it to XIVLauncher using its authenticator app/macros feature.

## How to use it
### Installation - from source

#### Dependencies
- Rust+Cargo installed
- Wallet which supports secret service (KWallet, Gnome Keyring, KeepassXC or oo7).

First, ensure you have the cargo install directory in your path (usually `$HOME/.cargo/bin`). You will also need to make sure you have "Use XIVLauncher authenticator app/macros" enabled in the XIVLauncher settings.
You can then download and install xiv-otp by running:
```bash
cargo install --git https://github.com/callummance/xiv-otp.git
```

### Use
You can setup xiv-otp by running `xiv-otp set-secret`, at which point it will ask you for your OTP secret. You can obtain this
either by copying and pasting it from the SE account management site or just copying it from your password manager if you already
have otp set up.
You can then login quickly by running `xiv-otp oneshot` whilst XIVLauncher is asking for an OTP, or run `xiv-otp monitor` to continuously wait for XIVLauncher to start up and submit an OTP token whenever needed.

## Security
Please remember that freedesktop secret service doesn't really implement access control, so once your wallet is unlocked any program running as your user can in theory read your OTP secret. Using KeepassXC or disabling auto login can mitigate this issue, but you still use this tool at your own risk.
