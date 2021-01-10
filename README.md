USAGE

```
git clone https://github.com/RIOT-OS/RIOT riot
git clone https://github.com/ant9000/saml21-aes-gcm
cd saml21-aes-gcm
make flash
make term
```

If you are not trying the code on a saml21-xpro board, adapt like this:

```
BOARD=samr34-xpro make flash
BOARD=samr34-xpro make term
```
