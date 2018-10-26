# nagios-plugin-check-certs ###

This Nagios plugin monitors expiration dates of x509 certificate files.
It suppors both recursing paths with certificates or single files.

#### Usage: #####
```
./check_certs.pl [flags] <path|file> ...

Flags:
-w <days>       Days left to expire before triggering a warning alert.
-c <days>       Days left to expire before triggering a critical alert.
-e <ext1,ext2>  File extensions to scan if a path is given.
```

#### Example: ####
```
$ ./check_certs.pl -w 30 -c 10 /etc/ssl-certs
CRITICAL: /etc/ssl-certs/*.mydomain.com/*.mydomain.com.crt expired on Aug 21 13:33:14 2018 GMT
WARNING: /etc/ssl-certs/myotherdomain.com/myotherdomain.com.crt expires in 18 days on Nov 14 11:26:12 2018 GMT
```

#### Requirements: #### 

- openssl
- date
