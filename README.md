# nagios-plugin-check-sslcert ###

This Nagios plugin monitors expiration dates of SSL certificates.
It suppors both recursing paths with certificates or single certificates.

#### Usage: #####
```
./check_sslcert.pl [flags] <path|file> ...

Flags:
-w <days>       Days left to expire before triggering a warning alert.
-c <days>       Days left to expire before triggering a critical alert.
-e <ext1,ext2>  File extensions to scan if a path is given.
```

#### Example: ####
```
$ ./check_sslcert.pl -w 30 -c 10 /home/oles/acme.sh
CRITICAL: /etc/ssl-certs/*.mydomain.com/*.mydomain.com.crt expired on Aug 21 13:33:14 2018 GMT
WARNING: /etc/ssl-certs/myotherdomain.com/myotherdomain.com.crt expires in 18 days on Nov 14 11:26:12 2018 GMT
```
